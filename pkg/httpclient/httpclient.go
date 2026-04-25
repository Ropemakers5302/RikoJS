package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rikojs/internal/config"
)

type HttpClient struct {
	client  *http.Client
	headers map[string]string
}

func NewClient(cfg *config.Config) *HttpClient {
	return &HttpClient{
		client: &http.Client{
			Timeout: time.Duration(cfg.Scan.Timeout) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		headers: map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
		},
	}
}

func (c *HttpClient) Get(ctx context.Context, targetURL string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, nil, err
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}

	return body, resp, nil
}

func (c *HttpClient) SetHeader(key, value string) {
	c.headers[key] = value
}

func ResolveURL(baseURL, refURL string) string {
	if strings.HasPrefix(refURL, "http://") || strings.HasPrefix(refURL, "https://") {
		return refURL
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	ref, err := url.Parse(refURL)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	return resolved.String()
}

func GetBaseURL(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}
