//go:build linux

package containerescape

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestProbeDockerAPIUsesOnlyBoundedGETs(t *testing.T) {
	var lock sync.Mutex
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		lock.Lock()
		requests = append(requests, request.Method+" "+request.URL.Path)
		lock.Unlock()
		switch request.URL.Path {
		case "/_ping":
			return response(http.StatusOK, "OK"), nil
		case "/version":
			return response(http.StatusOK, `{"Version":"26.0","ApiVersion":"1.45","Os":"linux","SensitiveIgnored":"value"}`), nil
		default:
			return response(http.StatusNotFound, "not found"), nil
		}
	})}
	result, err := probeDockerAPI(context.Background(), client, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != "26.0" || result.APIVersion != "1.45" || result.OS != "linux" {
		t.Fatalf("result = %#v", result)
	}
	lock.Lock()
	defer lock.Unlock()
	if got := strings.Join(requests, ","); got != "GET /_ping,GET /version" {
		t.Fatalf("requests = %q", got)
	}
}

func TestProbeDockerAPIBoundsResponses(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.Repeat("x", 65)), nil
	})}
	_, err := probeDockerAPI(context.Background(), client, 64)
	if err == nil || !strings.Contains(err.Error(), "exceeds 64-byte limit") {
		t.Fatalf("error = %v", err)
	}
}

func TestProbeDockerAPIValidatesResponses(t *testing.T) {
	tests := []struct {
		name      string
		transport roundTripFunc
		want      string
	}{
		{
			name: "ping status",
			transport: func(_ *http.Request) (*http.Response, error) {
				return response(http.StatusForbidden, "no"), nil
			},
			want: "HTTP status Forbidden",
		},
		{
			name: "unexpected ping",
			transport: func(_ *http.Request) (*http.Response, error) {
				return response(http.StatusOK, "not docker"), nil
			},
			want: "unexpected response",
		},
		{
			name: "malformed version",
			transport: func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/_ping" {
					return response(http.StatusOK, "OK"), nil
				}
				return response(http.StatusOK, "{"), nil
			},
			want: "decode Docker version response",
		},
		{
			name: "missing API version",
			transport: func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/_ping" {
					return response(http.StatusOK, "OK"), nil
				}
				return response(http.StatusOK, `{"Version":"test"}`), nil
			},
			want: "omitted ApiVersion",
		},
		{
			name: "unsafe API version",
			transport: func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == "/_ping" {
					return response(http.StatusOK, "OK"), nil
				}
				return response(http.StatusOK, "{\"ApiVersion\":\"1.45\\nforged\"}"), nil
			},
			want: "invalid ApiVersion",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := probeDockerAPI(context.Background(), &http.Client{Transport: test.transport}, 1024)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestProbeDockerAPIHonorsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	_, err := probeDockerAPI(ctx, client, 1024)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("error = %v", err)
	}
}
