package browserauth

import (
	"reflect"
	"testing"
)

func TestBrowserEnvironmentResetsAllGPSocksVariables(t *testing.T) {
	environ := []string{
		"PATH=C:\\Windows", "GP_SOCKS_PASSWORD=secret", "GP_SOCKS_USERNAME=alice",
		"gp_socks_debug_log=debug.jsonl", "UNRELATED=value", "GP_SOCKS_PASSWORD=duplicate",
	}
	want := []string{"GP_SOCKS_PASSWORD=", "GP_SOCKS_USERNAME=", "gp_socks_debug_log="}
	if got := browserEnvironmentResets(environ); !reflect.DeepEqual(got, want) {
		t.Fatalf("browserEnvironmentResets() = %v, want %v", got, want)
	}
}
