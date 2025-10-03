package workspace

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
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

	httpClient := newGitHubHTTPClient(ctx)
	client := github.NewClient(httpClient)

	archiveURL, _, err := client.Repositories.GetArchiveLink(ctx, owner, repo, github.Tarball, nil, 0)
	if err != nil {
		return fmt.Errorf("get repository archive link: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL.String(), nil)
	if err != nil {
		return fmt.Errorf("build repository archive request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download repository archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download repository archive: unexpected status %s", resp.Status)
	}

	if err := extractTarGz(resp.Body, destAbs); err != nil {
		return fmt.Errorf("extract repository archive: %w", err)
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

func newGitHubHTTPClient(ctx context.Context) *http.Client {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return http.DefaultClient
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return oauth2.NewClient(ctx, ts)
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

func extractTarGz(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("decompress repository archive: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}

	tarReader := tar.NewReader(gz)
	var root string
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read repository archive: %w", err)
		}

		name := header.Name
		if root == "" {
			root = strings.SplitN(name, "/", 2)[0]
		}
		if root != "" {
			name = strings.TrimPrefix(name, root)
		}
		name = strings.TrimPrefix(name, "/")
		if name == "" {
			continue
		}

		cleanName := filepath.Clean(name)
		if cleanName == "." || cleanName == "" {
			continue
		}

		fullPath := filepath.Join(dest, filepath.FromSlash(cleanName))
		rel, err := filepath.Rel(dest, fullPath)
		if err != nil {
			return fmt.Errorf("determine path for %q: %w", cleanName, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("repository archive contains invalid path: %q", cleanName)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(fullPath, header.FileInfo().Mode().Perm()); err != nil {
				return fmt.Errorf("create directory %q: %w", cleanName, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
				return fmt.Errorf("create parent for %q: %w", cleanName, err)
			}
			file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("create file %q: %w", cleanName, err)
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("write file %q: %w", cleanName, err)
			}
			if err := file.Close(); err != nil {
				return fmt.Errorf("close file %q: %w", cleanName, err)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
				return fmt.Errorf("create parent for symlink %q: %w", cleanName, err)
			}
			if err := os.Symlink(header.Linkname, fullPath); err != nil {
				return fmt.Errorf("create symlink %q -> %q: %w", cleanName, header.Linkname, err)
			}
		default:
			return fmt.Errorf("unsupported archive entry %q (type %d)", cleanName, header.Typeflag)
		}
	}

	return nil
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
