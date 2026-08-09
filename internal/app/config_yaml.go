package app

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

func decodeConfigNode(node *yaml.Node) (fileConfig, error) {
	var config fileConfig
	err := decodeMapping(node, "config", func(key string, value *yaml.Node) error {
		switch key {
		case "log_level":
			return decodeString(value, key, &config.LogLevel)
		case "probe":
			return decodeProbeNode(value, &config.Probe)
		case "auth":
			return decodeAuthNode(value, &config.Auth)
		case "serve":
			return decodeServeNode(value, &config.Serve)
		default:
			return fmt.Errorf("unknown config key %q", key)
		}
	})
	if err != nil {
		return fileConfig{}, fmt.Errorf("decode config mapping: %w", err)
	}
	return config, nil
}

func decodeProbeNode(node *yaml.Node, patch *probePatch) error {
	return decodeMapping(node, "probe", func(key string, value *yaml.Node) error {
		switch key {
		case "portal":
			return decodeString(value, key, &patch.Portal)
		case "host_id":
			return decodeString(value, key, &patch.HostID)
		case "sso_file":
			return decodeString(value, key, &patch.SSOFile)
		case "debug_log":
			return decodeString(value, key, &patch.DebugLog)
		default:
			return fmt.Errorf("unknown probe key %q", key)
		}
	})
}

func decodeAuthNode(node *yaml.Node, patch *authPatch) error {
	return decodeMapping(node, "auth", func(key string, value *yaml.Node) error {
		switch key {
		case "portal":
			return decodeString(value, key, &patch.Portal)
		case "host_id":
			return decodeString(value, key, &patch.HostID)
		case "browser":
			return decodeString(value, key, &patch.Browser)
		case "browser_path":
			return decodeString(value, key, &patch.BrowserPath)
		case "browser_profile_dir":
			return decodeString(value, key, &patch.BrowserProfileDir)
		case "timeout":
			return decodeString(value, key, &patch.Timeout)
		case "debug_log":
			return decodeString(value, key, &patch.DebugLog)
		default:
			return fmt.Errorf("unknown auth key %q", key)
		}
	})
}

func decodeServeNode(node *yaml.Node, patch *servePatch) error {
	return decodeMapping(node, "serve", func(key string, value *yaml.Node) error {
		switch key {
		case "listen":
			return decodeString(value, key, &patch.Listen)
		case "portal":
			return decodeString(value, key, &patch.Portal)
		case "gateway":
			return decodeString(value, key, &patch.Gateway)
		case "host_id":
			return decodeString(value, key, &patch.HostID)
		case "browser":
			return decodeString(value, key, &patch.Browser)
		case "browser_path":
			return decodeString(value, key, &patch.BrowserPath)
		case "browser_profile_dir":
			return decodeString(value, key, &patch.BrowserProfileDir)
		case "timeout":
			return decodeString(value, key, &patch.Timeout)
		case "debug_log":
			return decodeString(value, key, &patch.DebugLog)
		default:
			return fmt.Errorf("unknown serve key %q", key)
		}
	})
}

func decodeMapping(node *yaml.Node, name string, decodeField func(string, *yaml.Node) error) error {
	if err := rejectYAMLFeature(node, name); err != nil {
		return err
	}
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" {
		return fmt.Errorf("%s must be a YAML mapping", name)
	}
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("%s mapping is incomplete", name)
	}

	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]
		if err := rejectYAMLFeature(keyNode, name+" key"); err != nil {
			return err
		}
		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
			return fmt.Errorf("%s keys must be strings", name)
		}
		key := keyNode.Value
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate %s key %q", name, key)
		}
		seen[key] = struct{}{}
		if err := decodeField(key, valueNode); err != nil {
			return err
		}
	}
	return nil
}

func decodeString(node *yaml.Node, name string, target *optionalString) error {
	if err := rejectYAMLFeature(node, name); err != nil {
		return err
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("%s must be a YAML string", name)
	}
	*target = presentString(node.Value)
	return nil
}

func rejectYAMLFeature(node *yaml.Node, name string) error {
	if node.Kind == yaml.AliasNode || node.Alias != nil {
		return fmt.Errorf("%s must not use YAML aliases", name)
	}
	if node.Anchor != "" {
		return fmt.Errorf("%s must not use YAML anchors", name)
	}
	if node.Tag == "!!merge" {
		return fmt.Errorf("%s must not use YAML merge keys", name)
	}
	return nil
}
