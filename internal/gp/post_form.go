package gp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxGatewayResponseBytes = 1 << 20

type postFormRequest struct {
	stage    string
	endpoint string
	form     url.Values
	label    string
}

func (c Client) postForm(ctx context.Context, request postFormRequest) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, request.endpoint, strings.NewReader(request.form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", request.failureLabel(), err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "PAN GlobalProtect")
	debugEvent := newDebugHTTPEvent(request.stage, req, request.form)
	httpClient := *c.httpClient
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if logErr := c.logHTTP(debugEvent.withError()); logErr != nil {
			return nil, debugLogError(fmt.Errorf("post %s request: %w", request.failureLabel(), err), logErr)
		}
		return nil, fmt.Errorf("post %s request: %w", request.failureLabel(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponseBytes+1))
	if err != nil {
		if logErr := c.logHTTP(debugEvent.withStatus(resp.StatusCode)); logErr != nil {
			return nil, debugLogError(fmt.Errorf("read %s response: %w", request.failureLabel(), err), logErr)
		}
		return nil, fmt.Errorf("read %s response: %w", request.failureLabel(), err)
	}
	logErr := c.logHTTP(debugEvent.withResponse(resp.StatusCode, body))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		statusErr := error(ErrInvalidAuthArtifact)
		if request.stage == "gateway_login" && resp.StatusCode == 512 {
			statusErr = &GatewayAuthError{StatusCode: resp.StatusCode}
		}
		return nil, debugLogError(fmt.Errorf("%s status %d: %w", request.failureLabel(), resp.StatusCode, statusErr), logErr)
	}
	if len(body) > maxGatewayResponseBytes {
		return nil, debugLogError(fmt.Errorf("%s response too large: %w", request.failureLabel(), ErrInvalidAuthArtifact), logErr)
	}
	if logErr != nil {
		return nil, logErr
	}
	return body, nil
}

func (r postFormRequest) failureLabel() string {
	if r.label != "" {
		return r.label
	}
	return "gateway"
}
