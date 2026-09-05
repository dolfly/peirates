//go:build linux

package containerescape

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type dockerVersion struct {
	Version    string `json:"Version"`
	APIVersion string `json:"ApiVersion"`
	OS         string `json:"Os"`
}

type dockerProbeResult struct {
	Version    string
	APIVersion string
	OS         string
}

func probeDockerSocket(ctx context.Context, socketPath string, timeout time.Duration, maxBytes int64) (dockerProbeResult, error) {
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dialContext, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	return probeDockerAPI(probeContext, client, maxBytes)
}

func probeDockerAPI(ctx context.Context, client *http.Client, maxBytes int64) (dockerProbeResult, error) {
	ping, err := dockerGET(ctx, client, "/_ping", maxBytes)
	if err != nil {
		return dockerProbeResult{}, fmt.Errorf("Docker ping: %w", err)
	}
	if strings.TrimSpace(string(ping)) != "OK" {
		return dockerProbeResult{}, fmt.Errorf("Docker ping returned an unexpected response")
	}
	versionBody, err := dockerGET(ctx, client, "/version", maxBytes)
	if err != nil {
		return dockerProbeResult{}, fmt.Errorf("Docker version: %w", err)
	}
	var version dockerVersion
	if err := json.Unmarshal(versionBody, &version); err != nil {
		return dockerProbeResult{}, fmt.Errorf("decode Docker version response: %w", err)
	}
	if version.APIVersion == "" {
		return dockerProbeResult{}, fmt.Errorf("Docker version response omitted ApiVersion")
	}
	if !validDockerAPIVersion(version.APIVersion) {
		return dockerProbeResult{}, fmt.Errorf("Docker version response contains an invalid ApiVersion")
	}
	return dockerProbeResult{Version: version.Version, APIVersion: version.APIVersion, OS: version.OS}, nil
}

func validDockerAPIVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for _, character := range version {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
}

func dockerGET(ctx context.Context, client *http.Client, path string, maxBytes int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBytes))
		return nil, fmt.Errorf("HTTP status %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d-byte limit", maxBytes)
	}
	return body, nil
}
