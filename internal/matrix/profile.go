package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const userIDPlaceholder = "{user_id}"

// ProfileClient updates Matrix profile metadata through a deployment-supplied
// client API endpoint. The endpoint template must contain exactly one
// {user_id} placeholder.
type ProfileClient struct {
	endpointTemplate string
	httpClient       *http.Client
}

// NewProfileClient validates a deployment-supplied Matrix profile endpoint.
func NewProfileClient(endpointTemplate string, httpClient *http.Client) (*ProfileClient, error) {
	if strings.Count(endpointTemplate, userIDPlaceholder) != 1 {
		return nil, errors.New("Matrix profile URL template must contain exactly one {user_id} placeholder")
	}
	parsed, err := url.Parse(endpointTemplate)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Matrix profile URL template must be an absolute URL without userinfo, query, or fragment")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &ProfileClient{endpointTemplate: endpointTemplate, httpClient: httpClient}, nil
}

// SetDisplayName sets the profile display name for a Matrix user using the
// short-lived personal access token created for that agent.
func (c *ProfileClient) SetDisplayName(ctx context.Context, accessToken, userID, displayName string) error {
	if c == nil || c.httpClient == nil {
		return errors.New("Matrix profile client is not initialized")
	}
	if strings.TrimSpace(accessToken) == "" {
		return errors.New("Matrix profile access token is required")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("Matrix user ID is required")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 256 {
		return errors.New("Matrix display name must be 1-256 characters")
	}
	endpoint := strings.Replace(c.endpointTemplate, userIDPlaceholder, url.PathEscape(userID), 1)
	body, err := json.Marshal(map[string]string{"displayname": displayName})
	if err != nil {
		return fmt.Errorf("encode Matrix profile request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("create Matrix profile request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update Matrix profile: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("update Matrix profile returned HTTP %d", resp.StatusCode)
	}
	return nil
}
