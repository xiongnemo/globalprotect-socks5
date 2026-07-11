package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	version, err := versionFromRepository(context.Background(), ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(version)
}

func versionFromRepository(ctx context.Context, repository string) (string, error) {
	output, err := gitOutput(ctx, repository, "tag", "--merged", "HEAD", "--list", "v0.0.*", "--sort=-version:refname")
	if err != nil {
		return "", err
	}
	for _, tag := range strings.Fields(output) {
		patch, err := strconv.Atoi(strings.TrimPrefix(tag, "v0.0."))
		if err != nil || patch < 1 {
			continue
		}
		countOutput, err := gitOutput(ctx, repository, "rev-list", "--count", tag+"..HEAD")
		if err != nil {
			return "", err
		}
		count, err := strconv.Atoi(strings.TrimSpace(countOutput))
		if err != nil {
			return "", fmt.Errorf("parse commit count %q: %w", countOutput, err)
		}
		return fmt.Sprintf("v0.0.%d", patch+count), nil
	}
	return "v0.0.1", nil
}

func gitOutput(ctx context.Context, repository string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
