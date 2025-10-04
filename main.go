package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jtan2231/vizier-bot/workspace"
)

type interaction struct {
	ID            string                  `json:"id"`
	ApplicationID string                  `json:"application_id"`
	Token         string                  `json:"token"`
	Type          int                     `json:"type"`
	ChannelID     string                  `json:"channel_id"`
	Data          *applicationCommandData `json:"data,omitempty"`
}

type applicationCommandData struct {
	Name    string                         `json:"name"`
	Options []applicationCommandDataOption `json:"options"`
}

type applicationCommandDataOption struct {
	Name    string                         `json:"name"`
	Type    int                            `json:"type"`
	Value   json.RawMessage                `json:"value,omitempty"`
	Options []applicationCommandDataOption `json:"options,omitempty"`
}

type messageData struct {
	Content string `json:"content"`
}

type interactionResponse struct {
	Type int          `json:"type"`
	Data *messageData `json:"data,omitempty"`
}

const (
	interactionTypePing               = 1
	interactionTypeApplicationCommand = 2
)

const interactionCallbackTypeChannelMessageWithSource = 4

const discordAPIBaseURL = "https://discord.com/api/v10"

const maxDiscordMessageLength = 2000

const (
	applicationCommandTypeChatInput    = 1
	applicationCommandOptionTypeString = 3
)

func main() {
	log.Printf("starting vizier bot")
	publicKey, err := loadPublicKey(os.Getenv("DISCORD_PUBLIC_KEY"))
	if err != nil {
		log.Fatalf("failed to load DISCORD_PUBLIC_KEY: %v", err)
	}
	log.Printf("loaded public key")

	applicationID := strings.TrimSpace(os.Getenv("DISCORD_APPLICATION_ID"))
	if applicationID == "" {
		log.Fatalf("DISCORD_APPLICATION_ID is not configured")
	}
	log.Printf("application id configured: %s", applicationID)

	botToken := strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))
	if botToken == "" {
		log.Fatalf("DISCORD_BOT_TOKEN is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	log.Printf("registering slash command")
	if err := registerPrimaryCommand(ctx, applicationID, botToken); err != nil {
		log.Fatalf("failed to register vizier command: %v", err)
	}
	log.Printf("slash command registration complete")

	addr := listenAddr()
	mux := http.NewServeMux()
	mux.Handle("/interactions", interactionHandler(publicKey))

	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

func listenAddr() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	return ":" + port
}

func loadPublicKey(hexKey string) (ed25519.PublicKey, error) {
	if hexKey == "" {
		return nil, errors.New("missing value")
	}

	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid key length")
	}

	return ed25519.PublicKey(raw), nil
}

func interactionHandler(publicKey ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("/interactions request: method=%s, content-length=%d", r.Method, r.ContentLength)
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// if !verifyRequest(r, publicKey, body) {
		// 	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// 	return
		// }

		var envelope interaction
		if err := json.Unmarshal(body, &envelope); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		log.Printf("interaction received: id=%s type=%d", envelope.ID, envelope.Type)

		var resp interactionResponse
		switch envelope.Type {
		case interactionTypePing:
			log.Printf("interaction %s: ping received", envelope.ID)
			resp = interactionResponse{Type: interactionTypePing}
		case interactionTypeApplicationCommand:
			log.Printf("interaction %s: application command received", envelope.ID)
			resp = handleApplicationCommand(r.Context(), &envelope)
		default:
			log.Printf("interaction %s: unsupported type %d", envelope.ID, envelope.Type)
			resp = messageResponse(fmt.Sprintf("unsupported interaction type: %d", envelope.Type))
		}

		respondJSON(w, resp)
	})
}

func verifyRequest(r *http.Request, publicKey ed25519.PublicKey, body []byte) bool {
	signatureHex := r.Header.Get("X-Signature-Ed25519")
	timestamp := r.Header.Get("X-Signature-Timestamp")
	if signatureHex == "" || timestamp == "" {
		return false
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}

	message := make([]byte, len(timestamp)+len(body))
	copy(message, timestamp)
	copy(message[len(timestamp):], body)

	return ed25519.Verify(publicKey, message, signature)
}

func respondJSON(w http.ResponseWriter, payload interactionResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write response: %v", err)
	}
}

func handleApplicationCommand(ctx context.Context, env *interaction) interactionResponse {
	if env == nil {
		return messageResponse("missing interaction data")
	}
	data := env.Data
	if data == nil {
		return messageResponse("missing interaction data")
	}
	log.Printf("interaction %s: handling command %q", env.ID, data.Name)

	switch data.Name {
	case "vizier":
		return runVizierCommand(ctx, env)
	default:
		return messageResponse(fmt.Sprintf("unsupported command: %s", data.Name))
	}
}

func runVizierCommand(ctx context.Context, env *interaction) interactionResponse {
	repo, found, err := extractStringOption(env.Data.Options, "repo", "repository")
	if err != nil {
		log.Printf("failed to parse repo option: %v", err)
		return messageResponse("failed to parse repo option")
	}
	if !found || repo == "" {
		return messageResponse("missing required option: repo")
	}

	command, found, err := extractStringOption(env.Data.Options, "command", "input")
	if err != nil {
		log.Printf("failed to parse command option: %v", err)
		return messageResponse("failed to parse command option")
	}
	if !found || command == "" {
		return messageResponse("missing required option: command")
	}

	if env.ApplicationID == "" || env.Token == "" {
		log.Printf("interaction missing application metadata (application_id=%q, token present=%t)", env.ApplicationID, env.Token != "")
		return messageResponse("unable to acknowledge this interaction")
	}

	channelID := strings.TrimSpace(env.ChannelID)
	if channelID == "" {
		log.Printf("interaction %q missing channel id; skipping vizier execution", env.ID)
		return messageResponse("Unable to run vizier: could not determine the channel for follow-up messages.")
	}

	botToken := strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))
	if botToken == "" {
		log.Printf("DISCORD_BOT_TOKEN is not configured; unable to send vizier results")
		return messageResponse("Unable to run vizier: bot configuration is incomplete.")
	}

	runner := workspace.Runner{
		GitCloneTimeout: 1 * time.Minute,
		CommandTimeout:  2 * time.Minute,
	}
	log.Printf("interaction %s: starting vizier runner", env.ID)

	ack := acknowledgeInteraction()

	go func(interactionID, repoArg, runnerCommand, botSecret, channelID string, runConfig workspace.Runner) {
		jobCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		log.Printf("interaction %s: cloning repo %s and executing command", interactionID, repoArg)

		output, runErr := runConfig.Run(jobCtx, repoArg, runnerCommand)
		var message string
		if runErr != nil {
			log.Printf("vizier command %s failed: %v", interactionID, runErr)
			message = formatErrorMessage(runErr)
		} else {
			log.Printf("interaction %s: command completed successfully", interactionID)
			message = formatSuccessMessage(output)
		}

		notifyCtx, notifyCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer notifyCancel()
		log.Printf("interaction %s: sending follow-up message to channel %s", interactionID, channelID)
		if err := sendChannelMessage(notifyCtx, botSecret, channelID, message); err != nil {
			log.Printf("failed to send vizier result message for interaction %s: %v", interactionID, err)
		}
		log.Printf("interaction %s: follow-up message dispatched", interactionID)
	}(env.ID, repo, command, botToken, channelID, runner)

	return ack
}

func extractStringOption(options []applicationCommandDataOption, names ...string) (string, bool, error) {
	for _, opt := range options {
		if len(opt.Options) > 0 {
			if value, found, err := extractStringOption(opt.Options, names...); err != nil || found {
				return value, found, err
			}
			continue
		}
		for _, name := range names {
			if opt.Name != name {
				continue
			}
			if opt.Value == nil {
				return "", false, fmt.Errorf("option %s missing value", name)
			}
			var value string
			if err := json.Unmarshal(opt.Value, &value); err != nil {
				return "", false, fmt.Errorf("option %s: %w", name, err)
			}
			return strings.TrimSpace(value), true, nil
		}
	}
	return "", false, nil
}

const ackMessageContent = "Message received"

func acknowledgeInteraction() interactionResponse {
	return interactionResponse{
		Type: interactionCallbackTypeChannelMessageWithSource,
		Data: &messageData{Content: ackMessageContent},
	}
}

func messageResponse(content string) interactionResponse {
	if content == "" {
		content = "(no content)"
	}
	return interactionResponse{Type: interactionCallbackTypeChannelMessageWithSource, Data: &messageData{Content: content}}
}

func formatErrorMessage(runErr error) string {
	if runErr == nil {
		return "vizier run failed with no additional details"
	}

	detail := strings.TrimSpace(runErr.Error())
	if detail == "" {
		return "vizier run failed"
	}

	const prefix = "vizier run failed.\n```"
	const suffix = "\n```"
	budget := maxDiscordMessageLength - len(prefix) - len(suffix)
	if budget <= 0 {
		return "vizier run failed"
	}

	truncated := truncateToRunes(detail, budget)
	return prefix + truncated + suffix
}

func formatSuccessMessage(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "vizier run completed with no output"
	}

	const prefix = "vizier run completed.\n```"
	const suffix = "\n```"
	budget := maxDiscordMessageLength - len(prefix) - len(suffix)
	if budget <= 0 {
		return "vizier run completed"
	}

	truncated := truncateToRunes(trimmed, budget)
	return prefix + truncated + suffix
}

func truncateToRunes(text string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func sendChannelMessage(ctx context.Context, botToken, channelID, content string) error {
	if botToken == "" {
		return errors.New("missing bot token")
	}
	if channelID == "" {
		return errors.New("missing channel id")
	}
	payload := struct {
		Content string `json:"content"`
	}{
		Content: content,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal channel message payload: %w", err)
	}

	url := fmt.Sprintf("%s/channels/%s/messages", discordAPIBaseURL, channelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build channel message request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bot "+botToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send channel message request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		if readErr != nil {
			return fmt.Errorf("channel message request failed: status %s", resp.Status)
		}
		return fmt.Errorf("channel message request failed: status %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	return nil
}

type commandPayload struct {
	Name        string          `json:"name"`
	Type        int             `json:"type"`
	Description string          `json:"description"`
	Options     []commandOption `json:"options,omitempty"`
}

type commandOption struct {
	Type        int    `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

type commandResponse struct {
	ID string `json:"id"`
	commandPayload
}

func registerPrimaryCommand(ctx context.Context, applicationID, botToken string) error {
	if applicationID == "" {
		return errors.New("missing application id")
	}
	if botToken == "" {
		return errors.New("missing bot token")
	}

	desired := commandPayload{
		Name:        "vizier",
		Type:        applicationCommandTypeChatInput,
		Description: "Run vizier in a repository",
		Options: []commandOption{
			{
				Type:        applicationCommandOptionTypeString,
				Name:        "repo",
				Description: "Target repository (URL or owner/name)",
				Required:    true,
			},
			{
				Type:        applicationCommandOptionTypeString,
				Name:        "command",
				Description: "vizier command to execute",
				Required:    true,
			},
		},
	}

	commandsURL := fmt.Sprintf("%s/applications/%s/commands", discordAPIBaseURL, applicationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, commandsURL, nil)
	if err != nil {
		return fmt.Errorf("build command list request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+botToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch command list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		if readErr != nil {
			return fmt.Errorf("fetch command list failed: status %s", resp.Status)
		}
		return fmt.Errorf("fetch command list failed: status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var existing []commandResponse
	if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
		return fmt.Errorf("decode command list: %w", err)
	}

	var match *commandResponse
	for i := range existing {
		cmd := &existing[i]
		if cmd.Name == desired.Name && cmd.Type == desired.Type {
			match = cmd
			break
		}
	}

	if match != nil && commandDefinitionsMatch(match.commandPayload, desired) {
		log.Printf("vizier command already registered")
		return nil
	}

	body, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal command payload: %w", err)
	}

	if match == nil {
		if err := sendCommandMutation(ctx, http.MethodPost, commandsURL, botToken, body); err != nil {
			return fmt.Errorf("create vizier command: %w", err)
		}
		log.Printf("created vizier command")
		return nil
	}

	updateURL := fmt.Sprintf("%s/%s", commandsURL, match.ID)
	if err := sendCommandMutation(ctx, http.MethodPatch, updateURL, botToken, body); err != nil {
		return fmt.Errorf("update vizier command: %w", err)
	}
	log.Printf("updated vizier command")
	return nil
}

func sendCommandMutation(ctx context.Context, method, url, botToken string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build command request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send command request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		if readErr != nil {
			return fmt.Errorf("command request failed: status %s", resp.Status)
		}
		return fmt.Errorf("command request failed: status %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	return nil
}

func commandDefinitionsMatch(current, desired commandPayload) bool {
	if current.Name != desired.Name || current.Type != desired.Type || current.Description != desired.Description {
		return false
	}
	if len(current.Options) != len(desired.Options) {
		return false
	}
	currentByName := make(map[string]commandOption, len(current.Options))
	for _, opt := range current.Options {
		currentByName[opt.Name] = opt
	}
	for _, opt := range desired.Options {
		actual, ok := currentByName[opt.Name]
		if !ok {
			return false
		}
		if actual.Type != opt.Type || actual.Description != opt.Description || actual.Required != opt.Required {
			return false
		}
	}
	return true
}
