package app

import "testing"

func testOptionalString(value string) optionalString {
	return optionalString{value: value, present: true}
}

func assertOptionalString(t *testing.T, got optionalString, want string) {
	t.Helper()
	if !got.present {
		t.Fatalf("optional string present = false, want true for %q", want)
	}
	if got.value != want {
		t.Fatalf("optional string value = %q, want %q", got.value, want)
	}
}

func testLookupEnv(values map[string]string) lookupEnvFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
