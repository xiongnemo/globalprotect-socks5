package gp

import "strings"

func redactSensitiveTagAttributes(raw string) string {
	searchAt := 0
	for {
		openOffset := strings.IndexByte(raw[searchAt:], '<')
		if openOffset < 0 {
			return raw
		}
		openStart := searchAt + openOffset
		openEndOffset := strings.IndexByte(raw[openStart:], '>')
		if openEndOffset < 0 {
			return raw
		}
		openEnd := openStart + openEndOffset
		inside := raw[openStart+1 : openEnd]
		if strings.HasPrefix(strings.TrimSpace(inside), "/") {
			searchAt = openEnd + 1
			continue
		}
		name := tagName(inside)
		if name == "" || !isSensitiveName(name) {
			searchAt = openEnd + 1
			continue
		}
		replacement := "<" + name + ">"
		raw = raw[:openStart] + replacement + raw[openEnd+1:]
		searchAt = openStart + len(replacement)
	}
}
