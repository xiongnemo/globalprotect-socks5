package gp

import (
	"strings"
	"testing"
	"time"
)

func TestParseTunnelConfigRejectsInvalidLifecycleValues(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{name: "mtu", field: "mtu", value: "-1", want: "mtu"},
		{name: "lifetime", field: "lifetime", value: "not-seconds", want: "lifetime"},
		{name: "negative timeout", field: "timeout", value: "-1", want: "timeout"},
		{name: "overflow timeout", field: "timeout", value: "9223372036854775807", want: "timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := `<response><result><ip-address>10.0.0.2</ip-address><ssl-tunnel-url>/tunnel</ssl-tunnel-url><` +
				test.field + `>` + test.value + `</` + test.field + `></result></response>`
			_, err := parseTunnelConfig([]byte(body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseTunnelConfig() error = %v, want %s classification", err, test.want)
			}
		})
	}
}

func TestParseTunnelConfigKeepsShortRekeyInterval(t *testing.T) {
	config, err := parseTunnelConfig([]byte(`<response><result><ip-address>10.0.0.2</ip-address>` +
		`<ssl-tunnel-url>/tunnel</ssl-tunnel-url><timeout>30</timeout></result></response>`))
	if err != nil {
		t.Fatalf("parseTunnelConfig() error = %v", err)
	}
	if config.RekeyAfter != 30*time.Second {
		t.Fatalf("RekeyAfter = %s, want 30s", config.RekeyAfter)
	}
}
