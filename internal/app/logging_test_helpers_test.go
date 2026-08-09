package app

import (
	"bufio"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type logRecord map[string]string

func mustParseLogLevel(t *testing.T, raw string) logLevel {
	t.Helper()

	level, err := parseLogLevel(raw)
	if err != nil {
		t.Fatalf("parseLogLevel(%q) error = %v", raw, err)
	}
	return level
}

func decodeLogRecords(t *testing.T, output string) []logRecord {
	t.Helper()

	var records []logRecord
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var encoded map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &encoded); err != nil {
			t.Fatalf("decode application log record %q: %v", scanner.Text(), err)
		}

		record := make(logRecord, len(encoded))
		for key, rawValue := range encoded {
			var value string
			if err := json.Unmarshal(rawValue, &value); err != nil {
				t.Fatalf("application log field %q in %q is not a string: %v", key, scanner.Text(), err)
			}
			record[key] = value
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan application log: %v", err)
	}
	return records
}

func assertLogRecords(t *testing.T, got, want []logRecord) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("application log records = %#v, want %#v", got, want)
	}
}
