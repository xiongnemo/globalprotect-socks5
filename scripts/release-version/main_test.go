package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVersionFromRepository_returnsInitialVersion_withoutReleaseTag(t *testing.T) {
	// Given
	repository := newTestRepository(t)
	commitTestRepository(t, repository, 3)

	// When
	version, err := versionFromRepository(context.Background(), repository)

	// Then
	if err != nil {
		t.Fatalf("versionFromRepository() error = %v", err)
	}
	if version != "v0.0.1" {
		t.Fatalf("versionFromRepository() = %q, want v0.0.1", version)
	}
}

func TestVersionFromRepository_incrementsPatchByCommits_sinceReleaseTag(t *testing.T) {
	// Given
	repository := newTestRepository(t)
	commitTestRepository(t, repository, 1)
	runGit(t, repository, "tag", "v0.0.4")
	commitTestRepository(t, repository, 3)

	// When
	version, err := versionFromRepository(context.Background(), repository)

	// Then
	if err != nil {
		t.Fatalf("versionFromRepository() error = %v", err)
	}
	if version != "v0.0.7" {
		t.Fatalf("versionFromRepository() = %q, want v0.0.7", version)
	}
}

func TestVersionFromRepository_incrementsPatchOnFirstCommit_afterReleaseTag(t *testing.T) {
	// Given
	repository := newTestRepository(t)
	commitTestRepository(t, repository, 1)
	runGit(t, repository, "tag", "v0.0.1")
	commitTestRepository(t, repository, 1)

	// When
	version, err := versionFromRepository(context.Background(), repository)

	// Then
	if err != nil {
		t.Fatalf("versionFromRepository() error = %v", err)
	}
	if version != "v0.0.2" {
		t.Fatalf("versionFromRepository() = %q, want v0.0.2", version)
	}
}

func TestVersionFromRepository_keepsVersion_withoutNewCommit(t *testing.T) {
	// Given
	repository := newTestRepository(t)
	commitTestRepository(t, repository, 1)
	runGit(t, repository, "tag", "v0.0.8")

	// When
	version, err := versionFromRepository(context.Background(), repository)

	// Then
	if err != nil {
		t.Fatalf("versionFromRepository() error = %v", err)
	}
	if version != "v0.0.8" {
		t.Fatalf("versionFromRepository() = %q, want v0.0.8", version)
	}
}

func newTestRepository(t *testing.T) string {
	t.Helper()
	repository := filepath.Join(t.TempDir(), "repository")
	runGit(t, "", "init", repository)
	runGit(t, repository, "config", "user.name", "Release Test")
	runGit(t, repository, "config", "user.email", "release-test@example.invalid")
	return repository
}

func commitTestRepository(t *testing.T, repository string, count int) {
	t.Helper()
	for range count {
		runGit(t, repository, "commit", "--allow-empty", "-m", "test commit")
	}
}

func runGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v error = %v; output = %s", arguments, err, output)
	}
}
