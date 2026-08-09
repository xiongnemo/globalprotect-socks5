package app

import (
	"os"
	"reflect"
	"testing"
)

func TestRepositoryConfigTemplate_isStrictAndComplete(t *testing.T) {
	file, err := os.Open("../../config.yaml.template")
	if err != nil {
		t.Fatalf("Open(config.yaml.template) error = %v", err)
	}
	defer func() { _ = file.Close() }()

	config, err := decodeConfig(file)
	if err != nil {
		t.Fatalf("decodeConfig(config.yaml.template) error = %v", err)
	}
	want := fileConfig{
		LogLevel: defaultsFor(commandParseAuth).logLevel,
		Probe:    defaultsFor(commandProbe).probe,
		Auth:     defaultsFor(commandAuth).auth,
		Serve:    defaultsFor(commandServe).serve,
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("template config = %#v, want all defaults %#v", config, want)
	}
}
