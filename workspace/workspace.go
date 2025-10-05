package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	gitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
)

const maxRepositoryLogEntries = 100

var errRepositoryEntryLimit = errors.New("repository entry limit reached")

var plainCloneContext = git.PlainCloneContext

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

type repoWorkspace struct {
	root string
}

func newRepoWorkspace(path string) (*repoWorkspace, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("determine repository path: %w", err)
	}
	return &repoWorkspace{root: abs}, nil
}

func (rw *repoWorkspace) Root() string {
	if rw == nil {
		return ""
	}
	return rw.root
}

func (rw *repoWorkspace) Join(elements ...string) string {
	if rw == nil {
		return ""
	}
	if len(elements) == 0 {
		return rw.root
	}
	return filepath.Join(append([]string{rw.root}, elements...)...)
}

func (rw *repoWorkspace) Close() {
	if rw == nil {
		return
	}
	rw.root = ""
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
	repoScope, err := newRepoWorkspace(repoDir)
	if err != nil {
		return "", err
	}
	defer repoScope.Close()

	logRepositoryContents(repoURL, repoScope.Root())

	vizierPath := repoScope.Join("vizier")
	if err := r.fetchVizierBinary(ctx, vizierPath); err != nil {
		return "", err
	}

	return r.runVizier(ctx, repoScope, vizierPath, vizierCommand)
}

func logRepositoryContents(repoURL, repoDir string) {
	entries, truncated, err := gatherRepositoryEntries(repoDir)
	if err != nil {
		log.Printf("workspace: failed to list repository contents for %s: %v", repoURL, err)
		return
	}

	if len(entries) == 0 {
		log.Printf("workspace: repository %s has no files", repoURL)
		return
	}

	log.Printf("workspace: repository contents for %s (showing %d entries%s):", repoURL, len(entries), truncateSuffix(truncated))
	for _, entry := range entries {
		log.Printf("workspace: repo entry: %s", entry)
	}
	if truncated {
		log.Printf("workspace: repository contents truncated at %d entries", len(entries))
	}
}

func gatherRepositoryEntries(repoDir string) ([]string, bool, error) {
	entries := make([]string, 0, maxRepositoryLogEntries)
	truncated := false
	err := filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == repoDir {
			return nil
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if d.IsDir() {
			name += "/"
		}
		entries = append(entries, name)
		if len(entries) >= maxRepositoryLogEntries {
			truncated = true
			return errRepositoryEntryLimit
		}
		return nil
	})
	if err != nil && !errors.Is(err, errRepositoryEntryLimit) {
		return nil, false, err
	}
	return entries, truncated, nil
}

func truncateSuffix(truncated bool) string {
	if truncated {
		return ", truncated"
	}
	return ""
}

func (r Runner) cloneRepo(parentCtx context.Context, repoURL, dest string) error {
	ctx := parentCtx
	if r.GitCloneTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parentCtx, r.GitCloneTimeout)
		defer cancel()
	}

	owner, repo, err := parseGitHubRepo(repoURL)
	if err != nil {
		return err
	}

	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("determine destination path: %w", err)
	}

	if _, err := os.Stat(destAbs); err == nil {
		return fmt.Errorf("destination already exists: %s", destAbs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("validate destination: %w", err)
	}

	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	cloneOptions := &git.CloneOptions{
		URL:          cloneURL,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
	}
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		cloneOptions.Auth = &gitHTTP.BasicAuth{Username: "token", Password: token}
	}

	if _, err := plainCloneContext(ctx, destAbs, false, cloneOptions); err != nil {
		return fmt.Errorf("clone repository: %w", err)
	}

	if _, err := os.Stat(filepath.Join(destAbs, ".git")); err != nil {
		return fmt.Errorf("clone repository: missing git metadata: %w", err)
	}

	return nil
}

func (r Runner) fetchVizierBinary(parentCtx context.Context, dest string) error {
	releaseURL := "https://api.github.com/repos/OWNER/REPO/releases/latest"

	req, err := http.NewRequestWithContext(parentCtx, http.MethodGet, releaseURL, nil)
	if err != nil {
		return fmt.Errorf("build release request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch release info: unexpected status %s", resp.Status)
	}

	var release struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("decode release info: %w", err)
	}

	var vizierURL string
	for _, asset := range release.Assets {
		if asset.Name == "vizier" {
			vizierURL = asset.BrowserDownloadURL
			break
		}
	}

	if vizierURL == "" {
		return fmt.Errorf("vizier binary not found in release assets")
	}

	return r.downloadFromURL(parentCtx, vizierURL, dest)
}

func (r Runner) downloadFromURL(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download binary: unexpected status %s", resp.Status)
	}

	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create binary file: %w", err)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		file.Close()
		return fmt.Errorf("write binary: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close binary file: %w", err)
	}

	return nil
}

func (r Runner) runVizier(parentCtx context.Context, repo *repoWorkspace, vizierPath, vizierCommand string) (string, error) {
	ctx := parentCtx
	if r.CommandTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parentCtx, r.CommandTimeout)
		defer cancel()
	}

	repoRoot := repo.Root()
	if repoRoot == "" {
		return "", errors.New("workspace: repository frame is not active")
	}

	log.Printf("workspace: executing vizier binary %s with command %q in %s", vizierPath, vizierCommand, repoRoot)
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("%s %s", vizierPath, vizierCommand))
	cmd.Dir = repoRoot
	var combined bytes.Buffer
	cmd.Stdout = &combined
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vizier execution failed: %w: %s", err, strings.TrimSpace(combined.String()))
	}
	log.Printf("workspace: vizier command completed with %d bytes of output", combined.Len())

	return combined.String(), nil
}

func parseGitHubRepo(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimSuffix(trimmed, "/")
	trimmed = strings.TrimSuffix(trimmed, ".git")

	switch {
	case strings.HasPrefix(trimmed, "git@github.com:"):
		trimmed = strings.TrimPrefix(trimmed, "git@github.com:")
	case strings.HasPrefix(trimmed, "ssh://git@github.com/"):
		trimmed = strings.TrimPrefix(trimmed, "ssh://git@github.com/")
	case strings.HasPrefix(trimmed, "https://github.com/"):
		trimmed = strings.TrimPrefix(trimmed, "https://github.com/")
	case strings.HasPrefix(trimmed, "http://github.com/"):
		trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
	default:
		return "", "", fmt.Errorf("unsupported git host: %q", raw)
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid github repo: %q", raw)
	}

	return parts[0], parts[1], nil
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
