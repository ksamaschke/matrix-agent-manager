package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ksamaschke/matrix-agent-manager/internal/agents"
)

// RecoveryClientConfig contains the deployment-supplied homeserver base URL
// used for device checks. It must point at the Client-Server API root.
type RecoveryClientConfig struct {
	HomeserverBaseURL string
}

// RecoveryClient checks agent device state through the Matrix Client-Server
// API using the agent's own access token. It never persists keys.
type RecoveryClient struct {
	config     RecoveryClientConfig
	httpClient *http.Client
}

func NewRecoveryClient(config RecoveryClientConfig, httpClient *http.Client) (*RecoveryClient, error) {
	u, err := url.Parse(config.HomeserverBaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("homeserver base URL must be an absolute URL without userinfo")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RecoveryClient{config: config, httpClient: httpClient}, nil
}

// CheckDevice queries the homeserver for the device list of the authenticated
// user and reports whether deviceID is present and whether its identity keys
// are returned (i.e. the device is a usable E2EE device from the server's
// perspective). Verification is reported as false unless the server exposes
// trust state; the caller treats KeysMatch as the transport-health signal.
func (c *RecoveryClient) CheckDevice(ctx context.Context, accessToken, userID, deviceID string) (agents.DeviceStatus, error) {
	status := agents.DeviceStatus{DeviceID: deviceID}
	if strings.TrimSpace(accessToken) == "" || strings.TrimSpace(userID) == "" || strings.TrimSpace(deviceID) == "" {
		return status, fmt.Errorf("access token, user ID, and device ID are required")
	}
	endpoint := strings.TrimSuffix(c.config.HomeserverBaseURL, "/") + "/_matrix/client/v3/keys/query"
	body, err := json.Marshal(map[string]any{"device_keys": map[string][]string{userID: {}}})
	if err != nil {
		return status, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return status, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return status, fmt.Errorf("query device keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return status, fmt.Errorf("query device keys: homeserver returned %d", resp.StatusCode)
	}
	var parsed struct {
		DeviceKeys map[string]map[string]struct {
			Keys map[string]string `json:"keys"`
		} `json:"device_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return status, fmt.Errorf("decode device keys response: %w", err)
	}
	devices, ok := parsed.DeviceKeys[userID]
	if !ok {
		return status, nil
	}
	device, ok := devices[deviceID]
	if !ok {
		return status, nil
	}
	status.Known = true
	_, hasEd := device.Keys["ed25519:"+deviceID]
	_, hasCurve := device.Keys["curve25519:"+deviceID]
	status.KeysMatch = hasEd && hasCurve
	status.Verified = false
	return status, nil
}
