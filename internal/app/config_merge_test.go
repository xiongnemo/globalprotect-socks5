package app

import (
	"reflect"
	"testing"
)

func TestMergeProbe_overlaysOnlyPresentFields(t *testing.T) {
	// Given
	base := probePatch{
		Portal:   testOptionalString("base-portal"),
		HostID:   testOptionalString("base-host"),
		SSOFile:  testOptionalString("base-sso"),
		DebugLog: testOptionalString("base-debug"),
	}
	environment := probePatch{
		Portal:   testOptionalString("env-portal"),
		DebugLog: testOptionalString(""),
	}
	cli := probePatch{SSOFile: testOptionalString("cli-sso")}
	want := probePatch{
		Portal:   testOptionalString("env-portal"),
		HostID:   testOptionalString("base-host"),
		SSOFile:  testOptionalString("cli-sso"),
		DebugLog: testOptionalString(""),
	}

	// When
	got := mergeProbe(base, environment, cli)

	// Then
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeProbe() = %#v, want %#v", got, want)
	}
}

func TestMergeAuth_overlaysOnlyPresentFields(t *testing.T) {
	// Given
	base := authPatch{
		Portal:            testOptionalString("base-portal"),
		HostID:            testOptionalString("base-host"),
		Browser:           testOptionalString("auto"),
		BrowserPath:       testOptionalString("base-browser"),
		BrowserProfileDir: testOptionalString("base-profile"),
		Timeout:           testOptionalString("5m"),
		DebugLog:          testOptionalString("base-debug"),
	}
	environment := authPatch{
		Portal:      testOptionalString("env-portal"),
		BrowserPath: testOptionalString(""),
		Timeout:     testOptionalString("30s"),
	}
	cli := authPatch{
		Browser:  testOptionalString("chrome"),
		DebugLog: testOptionalString(""),
	}
	want := authPatch{
		Portal:            testOptionalString("env-portal"),
		HostID:            testOptionalString("base-host"),
		Browser:           testOptionalString("chrome"),
		BrowserPath:       testOptionalString(""),
		BrowserProfileDir: testOptionalString("base-profile"),
		Timeout:           testOptionalString("30s"),
		DebugLog:          testOptionalString(""),
	}

	// When
	got := mergeAuth(base, environment, cli)

	// Then
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeAuth() = %#v, want %#v", got, want)
	}
}

func TestMergeServe_overlaysOnlyPresentFields(t *testing.T) {
	// Given
	base := servePatch{
		Listen:            testOptionalString("base-listen"),
		Portal:            testOptionalString("base-portal"),
		Gateway:           testOptionalString("base-gateway"),
		HostID:            testOptionalString("base-host"),
		Browser:           testOptionalString("auto"),
		BrowserPath:       testOptionalString("base-browser"),
		BrowserProfileDir: testOptionalString("base-profile"),
		Timeout:           testOptionalString("5m"),
		DebugLog:          testOptionalString("base-debug"),
	}
	environment := servePatch{
		Portal:            testOptionalString("env-portal"),
		Gateway:           testOptionalString("env-gateway"),
		BrowserProfileDir: testOptionalString(""),
	}
	cli := servePatch{
		Listen:      testOptionalString("cli-listen"),
		Gateway:     testOptionalString("cli-gateway"),
		BrowserPath: testOptionalString("cli-browser"),
	}
	want := servePatch{
		Listen:            testOptionalString("cli-listen"),
		Portal:            testOptionalString("env-portal"),
		Gateway:           testOptionalString("cli-gateway"),
		HostID:            testOptionalString("base-host"),
		Browser:           testOptionalString("auto"),
		BrowserPath:       testOptionalString("cli-browser"),
		BrowserProfileDir: testOptionalString(""),
		Timeout:           testOptionalString("5m"),
		DebugLog:          testOptionalString("base-debug"),
	}

	// When
	got := mergeServe(base, environment, cli)

	// Then
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeServe() = %#v, want %#v", got, want)
	}
}
