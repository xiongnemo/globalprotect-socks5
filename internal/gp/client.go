package gp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout       = 30 * time.Second
	maxPreloginResponseBytes = 1 << 20
)

type PortalURL struct {
	raw *url.URL
}

func NewPortalURL(raw string) (PortalURL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return PortalURL{}, fmt.Errorf("parse portal url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return PortalURL{}, ErrInvalidPortalURL
	}
	return PortalURL{raw: parsed}, nil
}

func (u PortalURL) endpoint(path string) string {
	copyURL := *u.raw
	copyURL.Path = path
	copyURL.RawQuery = ""
	copyURL.Fragment = ""
	return copyURL.String()
}

type Client struct {
	httpClient *http.Client
	debugLog   *debugLogWriter
	profile    ClientProfile
}

type ClientOption func(*Client)

func NewClient(httpClient *http.Client, profile ClientProfile, options ...ClientOption) Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	httpClientCopy := *httpClient
	if httpClientCopy.Jar == nil {
		httpClientCopy.Jar, _ = cookiejar.New(nil)
	}
	client := Client{httpClient: &httpClientCopy, profile: profile}
	for _, option := range options {
		option(&client)
	}
	return client
}

func (c Client) Prelogin(ctx context.Context, portal PortalURL) (Prelogin, error) {
	form := c.preloginForm()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, portal.endpoint("/global-protect/prelogin.esp"), strings.NewReader(form.Encode()))
	if err != nil {
		return Prelogin{}, fmt.Errorf("create prelogin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "PAN GlobalProtect")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Prelogin{}, fmt.Errorf("post prelogin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Prelogin{}, fmt.Errorf("prelogin status %d: %w", resp.StatusCode, ErrInvalidPrelogin)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPreloginResponseBytes+1))
	if err != nil {
		return Prelogin{}, fmt.Errorf("read prelogin response: %w", err)
	}
	if len(body) > maxPreloginResponseBytes {
		return Prelogin{}, fmt.Errorf("prelogin response too large: %w", ErrInvalidPrelogin)
	}
	return ParsePrelogin(body)
}

func (c Client) preloginForm() url.Values {
	form := url.Values{}
	form.Set("tmp", "tmp")
	form.Set("clientVer", "4100")
	form.Set("host-id", c.profile.HostID)
	form.Set("computer", c.profile.Computer)
	form.Set("clientos", string(c.profile.ClientOS))
	form.Set("default-browser", "yes")
	form.Set("cas-support", "yes")
	return form
}
