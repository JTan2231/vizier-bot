package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const vizierBinaryURL = "https://github.com/JTan2231/vizier/releases/download/v0.0.1/vizier"

// Runner orchestrates cloning the repository, downloading the vizier binary,
// executing the provided command, and cleaning up the temporary workspace.
type Runner struct {
	// VizierURL defaults to the released vizier binary.
	VizierURL string
	// GitCloneTimeout bounds how long git clone is allowed to run.
	GitCloneTimeout time.Duration
	// CommandTimeout bounds how long the vizier command may run.
	CommandTimeout time.Duration
}

// Run sets up a temporary workspace, clones the target repository, downloads
// the vizier binary, runs vizier with the supplied command argument, and then
// removes the workspace. The combined stdout and stderr from vizier is
// returned on success. The caller is responsible for interpreting the output.
func (r Runner) Run(ctx context.Context, repoArg, vizierCommand string) (string, error) {
	if repoArg == "" {
		return "", errors.New("repo argument cannot be empty")
	}
	if vizierCommand == "" {
		return "", errors.New("command cannot be empty")
	}

	repoURL, err := resolveRepoURL(repoArg)
	if err != nil {
		return "", err
	}

	workspaceDir, err := os.MkdirTemp("", "vizier-work-")
	if err != nil {
		return "", fmt.Errorf("create workspace: %w", err)
	}
	defer os.RemoveAll(workspaceDir)

	repoDir := filepath.Join(workspaceDir, "repo")
	if err := r.cloneRepo(ctx, repoURL, repoDir); err != nil {
		return "", err
	}

	vizierPath := filepath.Join(repoDir, "vizier")
	if err := r.fetchVizierBinary(ctx, vizierPath); err != nil {
		return "", err
	}

	return r.runVizier(ctx, repoDir, vizierPath, vizierCommand)
}

func (r Runner) cloneRepo(parentCtx context.Context, repoURL, dest string) error {
	ctx := parentCtx
	if r.GitCloneTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parentCtx, r.GitCloneTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "./git", "clone", "--depth", "1", repoURL, dest)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}

func (r Runner) fetchVizierBinary(parentCtx context.Context, dest string) error {
	url := r.VizierURL
	if url == "" {
		url = vizierBinaryURL
	}

	req, err := http.NewRequestWithContext(parentCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build vizier request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download vizier: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download vizier: unexpected status %s", resp.Status)
	}

	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create vizier binary: %w", err)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		file.Close()
		return fmt.Errorf("write vizier binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close vizier binary: %w", err)
	}

	if err := os.Chmod(dest, 0o755); err != nil {
		return fmt.Errorf("set vizier permissions: %w", err)
	}

	return nil
}

func (r Runner) runVizier(parentCtx context.Context, repoDir, vizierPath, vizierCommand string) (string, error) {
	ctx := parentCtx
	if r.CommandTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parentCtx, r.CommandTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, vizierPath, vizierCommand)
	cmd.Dir = repoDir
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vizier execution failed: %w: %s", err, strings.TrimSpace(combined.String()))
	}

	return combined.String(), nil
}

func resolveRepoURL(repoArg string) (string, error) {
	if strings.HasPrefix(repoArg, "https://") || strings.HasPrefix(repoArg, "http://") || strings.HasPrefix(repoArg, "git@") {
		return repoArg, nil
	}

	if strings.Count(repoArg, "/") == 1 {
		return fmt.Sprintf("https://github.com/%s.git", repoArg), nil
	}

	if defaultOwner := os.Getenv("VIZIER_DEFAULT_REPO_OWNER"); defaultOwner != "" {
		return fmt.Sprintf("https://github.com/%s/%s.git", defaultOwner, repoArg), nil
	}

	return "", fmt.Errorf("unsupported repo format: %q", repoArg)
}
