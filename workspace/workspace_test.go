package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	gitTransport "github.com/go-git/go-git/v5/plumbing/transport"
	gitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func restorePlainCloneContext(t *testing.T) {
	t.Helper()
	original := plainCloneContext
	t.Cleanup(func() {
		plainCloneContext = original
	})
}

func TestCloneRepoUsesHTTPSAndAuth(t *testing.T) {
	restorePlainCloneContext(t)

	destRoot := t.TempDir()
	dest := filepath.Join(destRoot, "repo")

	t.Setenv("GITHUB_TOKEN", "secret-token")

	var (
		capturedURL  string
		capturedTags git.TagMode
		capturedAuth gitTransport.AuthMethod
		capturedPath string
		capturedBare bool
	)

	plainCloneContext = func(ctx context.Context, path string, isBare bool, opts *git.CloneOptions) (*git.Repository, error) {
		capturedURL = opts.URL
		capturedTags = opts.Tags
		capturedAuth = opts.Auth
		capturedPath = path
		capturedBare = isBare
		if err := os.MkdirAll(filepath.Join(path, ".git"), 0o755); err != nil {
			return nil, err
		}
		return nil, nil
	}

	var r Runner
	if err := r.cloneRepo(context.Background(), "git@github.com:owner/name.git", dest); err != nil {
		t.Fatalf("cloneRepo returned error: %v", err)
	}

	if capturedURL != "https://github.com/owner/name.git" {
		t.Fatalf("unexpected clone URL %q", capturedURL)
	}
	if capturedTags != git.AllTags {
		t.Fatalf("unexpected tag mode %v", capturedTags)
	}
	if capturedPath != dest {
		t.Fatalf("expected clone path %q, got %q", dest, capturedPath)
	}
	if capturedBare {
		t.Fatalf("expected non-bare clone")
	}

	basic, ok := capturedAuth.(*gitHTTP.BasicAuth)
	if !ok {
		t.Fatalf("expected BasicAuth, got %T", capturedAuth)
	}
	if basic.Username != "token" {
		t.Fatalf("unexpected auth username %q", basic.Username)
	}
	if basic.Password != "secret-token" {
		t.Fatalf("unexpected auth password %q", basic.Password)
	}
}

func TestCloneRepoRejectsExistingDestination(t *testing.T) {
	restorePlainCloneContext(t)

	called := false
	plainCloneContext = func(ctx context.Context, path string, isBare bool, opts *git.CloneOptions) (*git.Repository, error) {
		called = true
		return nil, nil
	}

	dest := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("failed to prepare destination: %v", err)
	}

	var r Runner
	err := r.cloneRepo(context.Background(), "https://github.com/owner/name.git", dest)
	if err == nil {
		t.Fatalf("expected error when destination exists")
	}
	if !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("expected clone helper not to be called")
	}
}

func TestCloneRepoValidatesGitMetadata(t *testing.T) {
	restorePlainCloneContext(t)

	plainCloneContext = func(ctx context.Context, path string, isBare bool, opts *git.CloneOptions) (*git.Repository, error) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, err
		}
		return nil, nil
	}

	dest := filepath.Join(t.TempDir(), "repo")

	var r Runner
	err := r.cloneRepo(context.Background(), "https://github.com/owner/name.git", dest)
	if err == nil {
		t.Fatalf("expected error when git metadata is missing")
	}
	if !strings.Contains(err.Error(), "missing git metadata") {
		t.Fatalf("unexpected error: %v", err)
	}
}
