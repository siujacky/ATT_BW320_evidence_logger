package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// apiClient talks to the running service's localhost dashboard API.
type apiClient struct {
	base string
	hc   *http.Client
}

// serviceAPI returns a client if the dashboard of the service using dataDir answers.
func serviceAPI(dataDir string) (*apiClient, bool) {
	listen := config.Default().Web.Listen
	if c, err := config.Load(config.PathsFor(dataDir).Config); err == nil {
		listen = c.Web.Listen
	}
	api := &apiClient{base: "http://" + listen, hc: &http.Client{Timeout: 10 * time.Minute}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api.base+"/api/status", nil)
	resp, err := api.hc.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	// Only use an instance that serves THIS data directory; another instance on the same port
	// (e.g. the installed service while testing with --data) must not receive our writes.
	var st struct {
		Ledger struct {
			DataDir string `json:"data_dir"`
		} `json:"ledger"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&st); err != nil {
		return nil, false
	}
	if st.Ledger.DataDir != "" && !samePath(st.Ledger.DataDir, dataDir) {
		return nil, false
	}
	return api, true
}

// samePath compares two Windows paths case-insensitively after cleaning.
func samePath(a, b string) bool {
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return strings.EqualFold(filepath.Clean(ca), filepath.Clean(cb))
}

func (a *apiClient) do(ctx context.Context, method, path string, in, out any) error {
	_, err := a.call(ctx, method, path, in, out)
	return err
}

// call is do, and also returns the response's header (nil when there was no response).
func (a *apiClient) call(ctx context.Context, method, path string, in, out any) (http.Header, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		req.Header.Set("X-ATT-Monitor", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode/100 != 2 {
		se := &serviceError{Status: resp.StatusCode, Body: data, msg: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			se.msg = e.Error
		}
		return resp.Header, se
	}
	if out == nil {
		return resp.Header, nil
	}
	return resp.Header, json.Unmarshal(data, out)
}

// download saves GET path into dir/name.
func (a *apiClient) download(ctx context.Context, path, dir, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(dst)
		return "", err
	}
	return dst, f.Close()
}

var errNoService = errors.New("service not running")

// serviceError is the service's answer to a request that failed: "service: " and its error
// message (or the HTTP status), with the status and the exact body (e.g. a failed configuration
// change also carries the change the monitor reported).
type serviceError struct {
	Status int
	Body   []byte
	msg    string
}

func (e *serviceError) Error() string { return "service: " + e.msg }

// reportedChange returns the change a failed configuration change's answer carries
// (web.ConfigChangeError), or nil.
func reportedChange(err error) *model.ConfigChange {
	var se *serviceError
	if !errors.As(err, &se) {
		return nil
	}
	var body struct {
		Change *model.ConfigChange `json:"change"`
	}
	if json.Unmarshal(se.Body, &body) != nil {
		return nil
	}
	return body.Change
}
