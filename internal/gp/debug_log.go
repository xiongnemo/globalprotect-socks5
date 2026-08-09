package gp

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	debugResponseSnippetBytes = 256
	redactedValue             = "[REDACTED]"
)

var (
	jsonSensitiveValueRe = regexp.MustCompile(`(?i)("[^"]*(token|cookie|auth|saml|assertion|secret|password|passwd|authorization)[^"]*"\s*:\s*)"([^"\\]|\\.)*"`)
	formSensitiveValueRe = regexp.MustCompile(`(?i)(^|[?&\s;])([^=?&\s;<>"']*(token|cookie|auth|saml|assertion|secret|password|passwd|authorization)[^=?&\s;<>"']*\s*=\s*)("[^"]*"|'[^']*'|[^&\s;<>"']*)`)
	inputNameValueRe     = regexp.MustCompile(`(?is)(<input\b[^>]*\bname\s*=\s*["'][^"']*(token|cookie|auth|saml|assertion|secret|password|passwd|authorization)[^"']*["'][^>]*\bvalue\s*=\s*["'])[^"']*`)
	inputValueNameRe     = regexp.MustCompile(`(?is)(<input\b[^>]*\bvalue\s*=\s*["'])[^"']*(["'][^>]*\bname\s*=\s*["'][^"']*(token|cookie|auth|saml|assertion|secret|password|passwd|authorization)[^"']*["'])`)
	bearerValueRe        = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
)

type debugLogWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

type debugHTTPEvent struct {
	Stage              string   `json:"stage"`
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	RequestFormFields  []string `json:"request_form_fields"`
	Status             int      `json:"status,omitempty"`
	ResponseSnippet    string   `json:"response_snippet,omitempty"`
	TransportSucceeded bool     `json:"transport_succeeded"`
	sensitiveValues    []string `json:"-"`
}

func WithDebugLog(w io.Writer) ClientOption {
	return func(client *Client) {
		if w != nil {
			client.debugLog = &debugLogWriter{enc: json.NewEncoder(w)}
		}
	}
}

func newDebugHTTPEvent(stage string, req *http.Request, form url.Values) debugHTTPEvent {
	return debugHTTPEvent{
		Stage:             stage,
		Method:            req.Method,
		Path:              req.URL.Path,
		RequestFormFields: sortedFormFields(form),
		sensitiveValues:   sensitiveFormValues(form),
	}
}

func (e debugHTTPEvent) withError() debugHTTPEvent {
	return e
}

func (e debugHTTPEvent) withStatus(status int) debugHTTPEvent {
	e.Status = status
	e.TransportSucceeded = true
	return e
}

func (e debugHTTPEvent) withResponse(status int, body []byte) debugHTTPEvent {
	e.Status = status
	if status < 200 || status >= 300 {
		e.ResponseSnippet = redactedSnippet(body, e.sensitiveValues...)
	}
	e.TransportSucceeded = true
	return e
}

func (c Client) logHTTP(event debugHTTPEvent) error {
	if c.debugLog == nil {
		return nil
	}
	return c.debugLog.write(event)
}

func (w *debugLogWriter) write(event debugHTTPEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.enc.Encode(event); err != nil {
		return fmt.Errorf("write debug log: %w", err)
	}
	return nil
}

func debugLogError(primary error, logErr error) error {
	if logErr == nil {
		return primary
	}
	return fmt.Errorf("%w; %w", primary, logErr)
}

func sortedFormFields(form url.Values) []string {
	fields := make([]string, 0, len(form))
	for field := range form {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func redactedSnippet(body []byte, sensitiveValues ...string) string {
	redacted := redactSensitiveContent(string(body))
	for _, value := range sensitiveValues {
		redacted = strings.ReplaceAll(redacted, value, redactedValue)
	}
	if len(redacted) <= debugResponseSnippetBytes {
		return redacted
	}
	snippet := redacted[:debugResponseSnippetBytes]
	for !utf8.ValidString(snippet) {
		snippet = snippet[:len(snippet)-1]
	}
	return snippet
}

func sensitiveFormValues(form url.Values) []string {
	unique := make(map[string]struct{})
	for field, values := range form {
		if !isSensitiveName(field) {
			continue
		}
		for _, value := range values {
			if !isSecretValue(value) {
				continue
			}
			for _, variant := range []string{value, url.QueryEscape(value), html.EscapeString(value)} {
				unique[variant] = struct{}{}
			}
		}
	}
	redactions := make([]string, 0, len(unique))
	for value := range unique {
		redactions = append(redactions, value)
	}
	sort.Slice(redactions, func(i, j int) bool { return len(redactions[i]) > len(redactions[j]) })
	return redactions
}

func isSecretValue(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "empty", "(null)", "-1":
		return false
	default:
		return true
	}
}

func redactSensitiveContent(raw string) string {
	redacted := redactSensitiveTagAttributes(raw)
	redacted = redactSensitiveAssignments(redacted)
	searchAt := 0
	for {
		start, end, ok := nextSensitiveTag(redacted, searchAt)
		if !ok {
			return redacted
		}
		redacted = redacted[:start] + redactedValue + redacted[end:]
		searchAt = start + len(redactedValue)
	}
}

func redactSensitiveAssignments(raw string) string {
	redacted := jsonSensitiveValueRe.ReplaceAllString(raw, `${1}"`+redactedValue+`"`)
	redacted = formSensitiveValueRe.ReplaceAllString(redacted, `${1}${2}`+redactedValue)
	redacted = inputNameValueRe.ReplaceAllString(redacted, `${1}`+redactedValue)
	redacted = inputValueNameRe.ReplaceAllString(redacted, `${1}`+redactedValue+`${2}`)
	return bearerValueRe.ReplaceAllString(redacted, `${1}`+redactedValue)
}

func nextSensitiveTag(raw string, searchAt int) (int, int, bool) {
	lower := strings.ToLower(raw)
	for {
		openStart := strings.IndexByte(lower[searchAt:], '<')
		if openStart < 0 {
			return 0, 0, false
		}
		openStart += searchAt
		if openStart+1 < len(lower) && lower[openStart+1] == '/' {
			searchAt = openStart + 1
			continue
		}
		openEnd := strings.IndexByte(lower[openStart:], '>')
		if openEnd < 0 {
			return 0, 0, false
		}
		openEnd += openStart
		name := tagName(lower[openStart+1 : openEnd])
		if name == "" || !isSensitiveName(name) {
			searchAt = openEnd + 1
			continue
		}
		closeTag := "</" + name + ">"
		closeStart := strings.Index(lower[openEnd+1:], closeTag)
		if closeStart < 0 {
			searchAt = openEnd + 1
			continue
		}
		closeStart += openEnd + 1
		return openEnd + 1, closeStart, true
	}
}

func tagName(raw string) string {
	name := strings.TrimSpace(raw)
	if i := strings.IndexAny(name, " \t\r\n/"); i >= 0 {
		name = name[:i]
	}
	return name
}

func isSensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"token", "cookie", "auth", "saml", "assertion", "secret", "password", "passwd", "authorization"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
