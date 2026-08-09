package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	yaml "go.yaml.in/yaml/v3"
)

const maxConfigBytes = 1 << 20

func decodeConfig(reader io.Reader) (fileConfig, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxConfigBytes+1))
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return fileConfig{}, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return fileConfig{}, fmt.Errorf("config document must not be empty")
		}
		return fileConfig{}, fmt.Errorf("decode YAML document: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			return fileConfig{}, fmt.Errorf("decode trailing YAML data: %w", err)
		}
		return fileConfig{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fileConfig{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	return decodeConfigNode(document.Content[0])
}

func loadConfig(path string, allowMissing bool) (config fileConfig, err error) {
	info, err := os.Stat(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return fileConfig{}, nil
		}
		return fileConfig{}, configOpenError(path, err)
	}
	if !info.Mode().IsRegular() {
		return fileConfig{}, configOpenError(path, fmt.Errorf("config is not a regular file"))
	}

	file, err := os.Open(path)
	if err != nil {
		return fileConfig{}, configOpenError(path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close config %q: %w", path, closeErr))
		}
	}()

	config, err = decodeConfig(file)
	if err != nil {
		return fileConfig{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	return config, nil
}

func configOpenError(path string, err error) error {
	return fmt.Errorf("open config %q: %w", path, withFailureMetadata(err, failureMetadata{
		stage: failureStageConfig,
		code:  failureCodeConfigOpen,
	}))
}
