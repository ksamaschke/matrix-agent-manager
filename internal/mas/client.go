package mas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// AdminScope is the MAS scope required by the Admin API.
	AdminScope       = "urn:mas:admin"
	maxResponseBytes = 1 << 20
)

// SecretReader supplies a secret value without putting it in configuration.
type SecretReader func(path string) ([]byte, error)

// ClientConfig contains explicit MAS endpoint and credential references.
// Endpoint URLs are inputs so deployments can choose their own service layout.
type ClientConfig struct {
	TokenURL            string
	UsersURL            string
	PersonalSessionsURL string
	ClientID            string
	ClientSecretFile    string
	HTTPClient          *http.Client
	AllowInsecureHTTP   bool
	BaseURL             string
}

// Client talks to the MAS Admin API using client credentials.
type Client struct {
	config      ClientConfig
	readSecret  SecretReader
	httpClient  *http.Client
	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// UserAttributes is the MAS Admin API user resource.
type UserAttributes struct {
	Username      string  `json:"username"`
	CreatedAt     string  `json:"created_at,omitempty"`
	LockedAt      *string `json:"locked_at,omitempty"`
	DeactivatedAt *string `json:"deactivated_at,omitempty"`
	Admin         bool    `json:"admin,omitempty"`
	LegacyGuest   bool    `json:"legacy_guest,omitempty"`
}

// User is a MAS Admin API user resource.
type User struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes UserAttributes `json:"attributes"`
}

// CreateUserRequest is the MAS v1.23 AddUserRequest schema.
type CreateUserRequest struct {
	Username            string  `json:"username"`
	SkipHomeserverCheck bool    `json:"skip_homeserver_check,omitempty"`
	DisplayName         *string `json:"displayname,omitempty"`
	AvatarURL           *string `json:"avatar_url,omitempty"`
}

// PersonalSessionAttributes is the MAS Admin API personal-session resource.
// AccessToken is populated only for create/regenerate responses.
type PersonalSessionAttributes struct {
	CreatedAt     string  `json:"created_at,omitempty"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
	OwnerUserID   *string `json:"owner_user_id,omitempty"`
	OwnerClientID *string `json:"owner_client_id,omitempty"`
	ActorUserID   string  `json:"actor_user_id"`
	HumanName     string  `json:"human_name"`
	Scope         string  `json:"scope"`
	LastActiveAt  *string `json:"last_active_at,omitempty"`
	LastActiveIP  *string `json:"last_active_ip,omitempty"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	AccessToken   string  `json:"access_token,omitempty"`
}

// PersonalSession is a MAS Admin API personal-session resource.
type PersonalSession struct {
	Type       string                    `json:"type"`
	ID         string                    `json:"id"`
	Attributes PersonalSessionAttributes `json:"attributes"`
}

// CreatePersonalSessionRequest is the MAS v1.23 schema.
type CreatePersonalSessionRequest struct {
	ActorUserID string  `json:"actor_user_id"`
	HumanName   string  `json:"human_name"`
	Scope       string  `json:"scope"`
	ExpiresIn   *uint32 `json:"expires_in,omitempty"`
}

// RegeneratePersonalSessionRequest is the MAS v1.23 schema.
type RegeneratePersonalSessionRequest struct {
	ExpiresIn *uint32 `json:"expires_in,omitempty"`
}

type deactivateUserRequest struct {
	SkipErase bool `json:"skip_erase,omitempty"`
}

type resource[T any] struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

type singleResponse[T any] struct {
	Data resource[T] `json:"data"`
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type paginatedSessionsResponse struct {
	Data  []resource[PersonalSessionAttributes] `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// NewClient validates the configured trust boundaries before creating a client.
func NewClient(config ClientConfig, readSecret SecretReader) (*Client, error) {
	for name, raw := range map[string]string{
		"TokenURL":            config.TokenURL,
		"UsersURL":            config.UsersURL,
		"PersonalSessionsURL": config.PersonalSessionsURL,
	} {
		if err := validateEndpoint(name, raw, config.AllowInsecureHTTP); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return nil, errors.New("ClientID is required")
	}
	if strings.TrimSpace(config.ClientSecretFile) == "" {
		return nil, errors.New("ClientSecretFile is required")
	}
	if readSecret == nil {
		readSecret = os.ReadFile
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if config.BaseURL != "" {
		if err := validateEndpoint("BaseURL", config.BaseURL, config.AllowInsecureHTTP); err != nil {
			return nil, err
		}
		base, _ := url.Parse(config.BaseURL)
		for name, raw := range map[string]string{"TokenURL": config.TokenURL, "UsersURL": config.UsersURL, "PersonalSessionsURL": config.PersonalSessionsURL} {
			u, _ := url.Parse(raw)
			if u.Scheme != base.Scheme || u.Host != base.Host {
				return nil, fmt.Errorf("%s must share the configured MAS origin", name)
			}
		}
	}
	if httpClient.CheckRedirect == nil {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			previous := via[len(via)-1].URL
			if req.URL.Scheme != previous.Scheme || req.URL.Host != previous.Host || req.URL.User != nil {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	return &Client{config: config, readSecret: readSecret, httpClient: httpClient}, nil
}

// CreateUser creates a MAS user and returns its resource metadata.
func (c *Client) CreateUser(ctx context.Context, request CreateUserRequest) (User, error) {
	var response singleResponse[UserAttributes]
	if err := c.doJSON(ctx, http.MethodPost, c.config.UsersURL, request, &response); err != nil {
		return User{}, err
	}
	return User{Type: response.Data.Type, ID: response.Data.ID, Attributes: response.Data.Attributes}, nil
}

// CreatePersonalSession creates a one-time personal access token.
func (c *Client) CreatePersonalSession(ctx context.Context, request CreatePersonalSessionRequest) (PersonalSession, error) {
	var response singleResponse[PersonalSessionAttributes]
	if err := c.doJSON(ctx, http.MethodPost, c.config.PersonalSessionsURL, request, &response); err != nil {
		return PersonalSession{}, err
	}
	return PersonalSession{Type: response.Data.Type, ID: response.Data.ID, Attributes: response.Data.Attributes}, nil
}

// RegeneratePersonalSession atomically replaces the token for an existing MAS
// personal session. The session ID remains stable and the previous token is
// invalidated by MAS as part of the operation.
func (c *Client) RegeneratePersonalSession(ctx context.Context, id string, expiresIn *uint32) (PersonalSession, error) {
	endpoint, err := resourceEndpoint(c.config.PersonalSessionsURL, id, "/regenerate")
	if err != nil {
		return PersonalSession{}, err
	}
	var response singleResponse[PersonalSessionAttributes]
	if err := c.doJSON(ctx, http.MethodPost, endpoint, RegeneratePersonalSessionRequest{ExpiresIn: expiresIn}, &response); err != nil {
		return PersonalSession{}, err
	}
	return PersonalSession{Type: response.Data.Type, ID: response.Data.ID, Attributes: response.Data.Attributes}, nil
}

// RevokePersonalSession revokes an existing MAS personal session.
func (c *Client) RevokePersonalSession(ctx context.Context, id string) error {
	endpoint, err := resourceEndpoint(c.config.PersonalSessionsURL, id, "/revoke")
	if err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodPost, endpoint, nil, nil)
}

// ListPersonalSessions lists personal sessions owned by the given MAS user.
// It follows only MAS-provided same-origin next links and bounds traversal.
func (c *Client) ListPersonalSessions(ctx context.Context, ownerUserID string) ([]PersonalSession, error) {
	if strings.TrimSpace(ownerUserID) == "" || strings.ContainsAny(ownerUserID, "/?#") {
		return nil, errors.New("MAS owner user ID is invalid")
	}
	endpoint, err := url.Parse(c.config.PersonalSessionsURL)
	if err != nil {
		return nil, fmt.Errorf("parse MAS sessions URL: %w", err)
	}
	query := endpoint.Query()
	query.Set("filter[actor_user]", ownerUserID)
	query.Set("filter[status]", "active")
	query.Set("page[first]", "100")
	endpoint.RawQuery = query.Encode()
	result := make([]PersonalSession, 0)
	for page := 0; page < 100 && endpoint != nil; page++ {
		var response paginatedSessionsResponse
		if err := c.doJSON(ctx, http.MethodGet, endpoint.String(), nil, &response); err != nil {
			return nil, err
		}
		for _, item := range response.Data {
			result = append(result, PersonalSession{Type: item.Type, ID: item.ID, Attributes: item.Attributes})
		}
		if response.Links.Next == "" {
			return result, nil
		}
		next, err := url.Parse(response.Links.Next)
		if err != nil {
			return nil, errors.New("MAS pagination link is invalid")
		}
		next = endpoint.ResolveReference(next)
		if next.Scheme != endpoint.Scheme || next.Host != endpoint.Host || next.User != nil {
			return nil, errors.New("MAS pagination link is not same-origin")
		}
		endpoint = next
	}
	return nil, errors.New("MAS session pagination exceeded safety limit")
}

// DeactivateUser deactivates a MAS user and returns the updated resource.
func (c *Client) DeactivateUser(ctx context.Context, id string, skipErase bool) (User, error) {
	endpoint, err := resourceEndpoint(c.config.UsersURL, id, "/deactivate")
	if err != nil {
		return User{}, err
	}
	var response singleResponse[UserAttributes]
	if err := c.doJSON(ctx, http.MethodPost, endpoint, deactivateUserRequest{SkipErase: skipErase}, &response); err != nil {
		return User{}, err
	}
	return User{Type: response.Data.Type, ID: response.Data.ID, Attributes: response.Data.Attributes}, nil
}

// DeleteUser deactivates a user and requests homeserver data erasure.
// MAS exposes deactivation rather than a separate hard-delete operation.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	_, err := c.DeactivateUser(ctx, id, false)
	return err
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, requestBody any, responseBody any) error {
	token, err := c.accessTokenFor(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode MAS request: %w", err)
		}
		body = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("create MAS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("MAS request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("MAS request returned HTTP %d", resp.StatusCode)
	}
	if responseBody == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil
	}
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(limited).Decode(responseBody); err != nil {
		return fmt.Errorf("decode MAS response: %w", err)
	}
	return nil
}

func (c *Client) accessTokenFor(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}
	secret, err := c.readSecret(c.config.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("read MAS client secret: %w", err)
	}
	secretValue := strings.TrimSpace(string(secret))
	if secretValue == "" {
		return "", errors.New("MAS client secret is empty")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", AdminScope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create MAS token request: %w", err)
	}
	req.SetBasicAuth(c.config.ClientID, secretValue)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("MAS token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("MAS token request returned HTTP %d", resp.StatusCode)
	}
	var tokenResponse accessTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("decode MAS token response: %w", err)
	}
	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return "", errors.New("MAS token response did not contain an access token")
	}
	c.accessToken = tokenResponse.AccessToken
	if tokenResponse.ExpiresIn > 30 {
		c.tokenExpiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn-30) * time.Second)
	} else {
		c.tokenExpiry = time.Now()
	}
	return c.accessToken, nil
}

func validateEndpoint(name, raw string, allowInsecureHTTP bool) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is required", name)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && !(allowInsecureHTTP && u.Scheme == "http")) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTPS URL without userinfo, query, or fragment", name)
	}
	return nil
}

func resourceEndpoint(collection, id, suffix string) (string, error) {
	if strings.TrimSpace(id) == "" || strings.ContainsAny(id, "/?#") {
		return "", errors.New("MAS resource ID is invalid")
	}
	u, err := url.Parse(collection)
	if err != nil {
		return "", fmt.Errorf("parse MAS collection URL: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(id) + suffix
	return u.String(), nil
}
