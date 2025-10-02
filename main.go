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

const interactionCallbackTypeDeferredChannelMessage = 5

const discordAPIBaseURL = "https://discord.com/api/v10"

const maxDiscordMessageLength = 2000

func main() {
	publicKey, err := loadPublicKey(os.Getenv("DISCORD_PUBLIC_KEY"))
	if err != nil {
		log.Fatalf("failed to load DISCORD_PUBLIC_KEY: %v", err)
	}

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
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !verifyRequest(r, publicKey, body) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		var envelope interaction
		if err := json.Unmarshal(body, &envelope); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		var resp interactionResponse
		switch envelope.Type {
		case interactionTypePing:
			resp = interactionResponse{Type: interactionTypePing}
		case interactionTypeApplicationCommand:
			resp = handleApplicationCommand(r.Context(), &envelope)
		default:
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
	botToken := strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))

	runner := workspace.Runner{
		GitCloneTimeout: 1 * time.Minute,
		CommandTimeout:  2 * time.Minute,
	}

	defaultAck := fmt.Sprintf("Queued vizier run for `%s`. Results will follow here shortly.", repo)
	shouldRun := true
	if channelID == "" {
		log.Printf("interaction %q missing channel id; skipping vizier execution", env.ID)
		defaultAck = "Unable to run vizier: could not determine the channel for follow-up messages."
		shouldRun = false
	} else if botToken == "" {
		log.Printf("DISCORD_BOT_TOKEN is not configured; unable to send vizier results")
		defaultAck = "Unable to run vizier: bot configuration is incomplete."
		shouldRun = false
	}
	ackMessage := truncateToRunes(defaultAck, maxDiscordMessageLength)

	go func(interactionID, appID, token, repoArg, runnerCommand, botSecret, channelID, ack string, run bool, runConfig workspace.Runner) {
		jobCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		output, runErr := runConfig.Run(jobCtx, repoArg, runnerCommand)
		var message string
		if runErr != nil {
			log.Printf("vizier command %s failed: %v", interactionID, runErr)
			message = "testing!" //formatErrorMessage(runErr)
		} else {
			message = formatSuccessMessage(output)
		}

		notifyCtx, notifyCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer notifyCancel()
		if err := sendChannelMessage(notifyCtx, botSecret, channelID, message); err != nil {
			log.Printf("failed to send vizier result message for interaction %s: %v", interactionID, err)
		}
	}(env.ID, env.ApplicationID, env.Token, repo, command, botToken, channelID, ackMessage, shouldRun, runner)

	return interactionResponse{Type: interactionCallbackTypeDeferredChannelMessage}
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

func messageResponse(content string) interactionResponse {
	if content == "" {
		content = "(no content)"
	}
	return interactionResponse{Type: 4, Data: &messageData{Content: content}}
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

func formatErrorMessage(err error) string {
	const prefix = "vizier run failed: "
	budget := maxDiscordMessageLength - len(prefix)
	if budget <= 0 {
		return prefix
	}
	msg := err.Error()
	truncated := truncateToRunes(msg, budget)
	return prefix + truncated
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
