package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	userIDPlaceholder      = "{user_id}"
	maxAvatarResponseBytes = 5 << 20
)

// ProfileClientConfig contains deployment-supplied Matrix Client-Server API
// endpoints. Avatar support is enabled when all avatar endpoint fields are configured.
type ProfileClientConfig struct {
	DisplayNameURLTemplate    string
	AvatarURLTemplate         string
	MediaUploadURL            string
	MediaThumbnailURLTemplate string
	MatrixServerName          string
}

// ProfileClient updates Matrix profile metadata and uploads avatar media using
// the agent's personal access token.
type ProfileClient struct {
	config     ProfileClientConfig
	httpClient *http.Client
}

// NewProfileClient retains the display-name-only constructor used by existing
// callers and tests. Avatar operations require NewProfileClientWithConfig.
func NewProfileClient(endpointTemplate string, httpClient *http.Client) (*ProfileClient, error) {
	return NewProfileClientWithConfig(ProfileClientConfig{DisplayNameURLTemplate: endpointTemplate}, httpClient)
}

// NewProfileClientWithConfig validates deployment-supplied Matrix endpoints.
func NewProfileClientWithConfig(config ProfileClientConfig, httpClient *http.Client) (*ProfileClient, error) {
	if err := validateProfileTemplate("Matrix display name URL template", config.DisplayNameURLTemplate); err != nil {
		return nil, err
	}
	profileEndpoint, _ := url.Parse(config.DisplayNameURLTemplate)
	profileOrigin := endpointOrigin(profileEndpoint)
	if strings.TrimSpace(config.MatrixServerName) != "" {
		if err := validateMatrixServerName(config.MatrixServerName); err != nil {
			return nil, err
		}
	}
	avatarConfigured := strings.TrimSpace(config.AvatarURLTemplate) != "" || strings.TrimSpace(config.MediaUploadURL) != ""
	if avatarConfigured {
		if err := validateProfileTemplate("Matrix avatar URL template", config.AvatarURLTemplate); err != nil {
			return nil, err
		}
		if err := validateAbsoluteURL("Matrix media upload URL", config.MediaUploadURL); err != nil {
			return nil, err
		}
		if err := validateMediaThumbnailTemplate(config.MediaThumbnailURLTemplate); err != nil {
			return nil, err
		}
		avatarEndpoint, _ := url.Parse(config.AvatarURLTemplate)
		mediaEndpoint, _ := url.Parse(config.MediaUploadURL)
		thumbnailEndpoint, _ := url.Parse(config.MediaThumbnailURLTemplate)
		if endpointOrigin(avatarEndpoint) != profileOrigin || endpointOrigin(mediaEndpoint) != profileOrigin || endpointOrigin(thumbnailEndpoint) != profileOrigin {
			return nil, errors.New("Matrix profile and avatar endpoints must share one origin")
		}
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	if clientCopy.CheckRedirect == nil {
		clientCopy.CheckRedirect = sameOriginRedirect
	}
	return &ProfileClient{config: config, httpClient: &clientCopy}, nil
}

// SetDisplayName sets the profile display name for a Matrix user.
func (c *ProfileClient) SetDisplayName(ctx context.Context, accessToken, userID, displayName string) error {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 256 {
		return errors.New("Matrix display name must be 1-256 characters")
	}
	return c.setProfileValue(ctx, accessToken, userID, c.config.DisplayNameURLTemplate, "displayname", displayName)
}

// UploadAvatar uploads image bytes to the Matrix media repository and returns
// the mxc:// content URI assigned by the homeserver.
func (c *ProfileClient) UploadAvatar(ctx context.Context, accessToken, filename, contentType string, data []byte) (string, error) {
	if c == nil || c.httpClient == nil {
		return "", errors.New("Matrix profile client is not initialized")
	}
	if strings.TrimSpace(c.config.MediaUploadURL) == "" {
		return "", errors.New("Matrix avatar upload is not configured")
	}
	if strings.TrimSpace(accessToken) == "" {
		return "", errors.New("Matrix profile access token is required")
	}
	if len(data) == 0 {
		return "", errors.New("Matrix avatar data is required")
	}
	filename = path.Base(strings.TrimSpace(filename))
	if filename == "." || filename == "" || strings.ContainsAny(filename, "\x00\r\n") {
		return "", errors.New("Matrix avatar filename is invalid")
	}
	contentType = strings.TrimSpace(contentType)
	if !strings.HasPrefix(contentType, "image/") {
		return "", errors.New("Matrix avatar content type must be an image")
	}
	endpoint, err := url.Parse(c.config.MediaUploadURL)
	if err != nil {
		return "", fmt.Errorf("parse Matrix media upload URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("filename", filename)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create Matrix avatar upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", contentType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload Matrix avatar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("upload Matrix avatar returned HTTP %d", resp.StatusCode)
	}
	var response struct {
		ContentURI string `json:"content_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&response); err != nil {
		return "", fmt.Errorf("decode Matrix avatar upload response: %w", err)
	}
	if err := validateMXCURIForServer(response.ContentURI, c.config.MatrixServerName); err != nil {
		return "", fmt.Errorf("Matrix avatar upload returned invalid content URI: %w", err)
	}
	return response.ContentURI, nil
}

// FetchAvatar downloads a bounded thumbnail through the configured Matrix media
// endpoint using the agent token. The token never leaves the server.
func (c *ProfileClient) FetchAvatar(ctx context.Context, accessToken, avatarURL string) ([]byte, string, error) {
	if c == nil || c.httpClient == nil {
		return nil, "", errors.New("Matrix profile client is not initialized")
	}
	if strings.TrimSpace(c.config.MediaThumbnailURLTemplate) == "" {
		return nil, "", errors.New("Matrix avatar thumbnail endpoint is not configured")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, "", errors.New("Matrix profile access token is required")
	}
	if err := validateMXCURIForServer(avatarURL, c.config.MatrixServerName); err != nil {
		return nil, "", fmt.Errorf("Matrix avatar URL is invalid: %w", err)
	}
	parsed, _ := url.Parse(strings.TrimSpace(avatarURL))
	mediaID := strings.TrimPrefix(parsed.Path, "/")
	endpoint := strings.Replace(c.config.MediaThumbnailURLTemplate, "{server_name}", url.PathEscape(parsed.Host), 1)
	endpoint = strings.Replace(endpoint, "{media_id}", url.PathEscape(mediaID), 1)
	thumbnailURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("parse Matrix avatar thumbnail URL: %w", err)
	}
	query := thumbnailURL.Query()
	query.Set("width", "96")
	query.Set("height", "96")
	query.Set("method", "scale")
	thumbnailURL.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, thumbnailURL.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("create Matrix avatar thumbnail request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch Matrix avatar thumbnail: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("fetch Matrix avatar thumbnail returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAvatarResponseBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read Matrix avatar thumbnail: %w", err)
	}
	if len(data) > maxAvatarResponseBytes {
		return nil, "", errors.New("Matrix avatar thumbnail is too large")
	}
	contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = http.DetectContentType(data)
	}
	if !strings.HasPrefix(contentType, "image/") {
		return nil, "", errors.New("Matrix avatar thumbnail is not an image")
	}
	return data, contentType, nil
}

// empty value clears the avatar during best-effort rollback.
func (c *ProfileClient) SetAvatarURL(ctx context.Context, accessToken, userID, avatarURL string) error {
	if strings.TrimSpace(avatarURL) != "" {
		if err := validateMXCURIForServer(avatarURL, c.config.MatrixServerName); err != nil {
			return fmt.Errorf("Matrix avatar URL is invalid: %w", err)
		}
	}
	return c.setProfileValue(ctx, accessToken, userID, c.config.AvatarURLTemplate, "avatar_url", avatarURL)
}

func (c *ProfileClient) setProfileValue(ctx context.Context, accessToken, userID, endpointTemplate, key, value string) error {
	if c == nil || c.httpClient == nil {
		return errors.New("Matrix profile client is not initialized")
	}
	if strings.TrimSpace(endpointTemplate) == "" {
		return fmt.Errorf("Matrix profile %s endpoint is not configured", key)
	}
	if strings.TrimSpace(accessToken) == "" {
		return errors.New("Matrix profile access token is required")
	}
	if strings.TrimSpace(userID) == "" {
		return errors.New("Matrix user ID is required")
	}
	endpoint := strings.Replace(endpointTemplate, userIDPlaceholder, url.PathEscape(userID), 1)
	body, err := json.Marshal(map[string]string{key: value})
	if err != nil {
		return fmt.Errorf("encode Matrix profile request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
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

func endpointOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func validateProfileTemplate(name, raw string) error {
	if strings.Count(raw, userIDPlaceholder) != 1 {
		return fmt.Errorf("%s must contain exactly one {user_id} placeholder", name)
	}
	return validateAbsoluteURL(name, raw)
}

func validateMediaThumbnailTemplate(raw string) error {
	if strings.Count(raw, "{server_name}") != 1 || strings.Count(raw, "{media_id}") != 1 {
		return errors.New("Matrix media thumbnail URL template must contain one {server_name} and one {media_id} placeholder")
	}
	return validateAbsoluteURL("Matrix media thumbnail URL template", raw)
}

func validateAbsoluteURL(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute URL without userinfo, query, or fragment", name)
	}
	return nil
}

func validateMatrixServerName(raw string) error {
	serverName := strings.TrimSpace(raw)
	if serverName == "" || strings.ContainsAny(serverName, "/?#@ \t\r\n") {
		return errors.New("Matrix server name is invalid")
	}
	return nil
}

func validateMXCURIForServer(raw, serverName string) error {
	if err := validateMXCURI(raw); err != nil {
		return err
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return nil
	}
	if err := validateMatrixServerName(serverName); err != nil {
		return err
	}
	parsed, _ := url.Parse(strings.TrimSpace(raw))
	if !strings.EqualFold(parsed.Host, serverName) {
		return fmt.Errorf("server name %q is not the configured Matrix server", parsed.Host)
	}
	return nil
}

func validateMXCURI(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "mxc" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must be an mxc:// URI")
	}
	mediaID := strings.TrimPrefix(parsed.Path, "/")
	if mediaID == "" || strings.Contains(mediaID, "/") {
		return errors.New("must contain one media ID")
	}
	return nil
}

func sameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	previous := via[len(via)-1].URL
	if req.URL.Scheme != previous.Scheme || req.URL.Host != previous.Host || req.URL.User != nil {
		return http.ErrUseLastResponse
	}
	return nil
}
