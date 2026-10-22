// Package cf is a minimal client for the parts of the Cloudflare API that
// cfkey needs: verifying, creating, listing and deleting user API tokens,
// and looking up permission groups, accounts and zones.
package cf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the only API endpoint used in production. It is
// deliberately not configurable from the environment: a redirected base URL
// would send the master token to whoever controls that URL.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// Client talks to the Cloudflare API with a single bearer token.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client authenticated with token.
func New(token string) *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// NewWithBaseURL is for tests that run against a fake API server.
func NewWithBaseURL(token, baseURL string) *Client {
	c := New(token)
	c.baseURL = strings.TrimRight(baseURL, "/")
	return c
}

// Forget drops the client's reference to its token. Go cannot guarantee the
// bytes are wiped from memory, but the client becomes unusable.
func (c *Client) Forget() { c.token = "" }

// Token is a Cloudflare user API token.
type Token struct {
	ID        string     `json:"id,omitempty"`
	Name      string     `json:"name"`
	Status    string     `json:"status,omitempty"`
	ExpiresOn string     `json:"expires_on,omitempty"`
	Policies  []Policy   `json:"policies"`
	Condition *Condition `json:"condition,omitempty"`
	// Value is the secret; Cloudflare returns it only on creation.
	Value string `json:"value,omitempty"`
}

// Policy grants permission groups on a set of resources. Resources is kept
// as raw JSON so policies can be copied without losing nested structure.
type Policy struct {
	ID               string            `json:"id,omitempty"`
	Effect           string            `json:"effect"`
	Resources        json.RawMessage   `json:"resources"`
	PermissionGroups []PermissionGroup `json:"permission_groups"`
}

// PermissionGroup is a named permission such as "DNS Write". Scopes says
// which kind of resource it applies to (zone, account, user, ...).
type PermissionGroup struct {
	ID     string   `json:"id"`
	Name   string   `json:"name,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// Condition restricts where a token may be used from.
type Condition struct {
	RequestIP *IPCondition `json:"request_ip,omitempty"`
}

// IPCondition lists allowed and denied client CIDRs.
type IPCondition struct {
	In    []string `json:"in,omitempty"`
	NotIn []string `json:"not_in,omitempty"`
}

// Account is a Cloudflare account.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Zone is a Cloudflare zone (domain).
type Zone struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Account Account `json:"account"`
}

// FormatTime renders t the way the tokens API expects (UTC, no fraction).
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// APIError is returned when Cloudflare answers with success=false.
type APIError struct {
	Status   int
	Messages []string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare API error (HTTP %d): %s", e.Status, strings.Join(e.Messages, "; "))
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) (*envelope, error) {
	if c.token == "" {
		return nil, fmt.Errorf("cloudflare client has no token")
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("cloudflare API: HTTP %d with unparseable body", resp.StatusCode)
	}
	if !env.Success || resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%s (code %d)", m.Message, m.Code))
		}
		if len(e.Messages) == 0 {
			e.Messages = []string{"unknown error"}
		}
		return nil, e
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare API: decoding result: %w", err)
		}
	}
	return &env, nil
}

// getAll follows page-based pagination and appends every page to out.
func getAll[T any](ctx context.Context, c *Client, path string, q url.Values) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		q.Set("page", fmt.Sprint(page))
		q.Set("per_page", "50")
		var items []T
		env, err := c.do(ctx, http.MethodGet, path+"?"+q.Encode(), nil, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if env.ResultInfo == nil || page >= env.ResultInfo.TotalPages || len(items) == 0 {
			return all, nil
		}
	}
}

// VerifyToken returns the ID and status of the client's own token.
func (c *Client) VerifyToken(ctx context.Context) (Token, error) {
	var t Token
	_, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil, &t)
	return t, err
}

// GetToken fetches a token's metadata, including its policies.
func (c *Client) GetToken(ctx context.Context, id string) (Token, error) {
	var t Token
	_, err := c.do(ctx, http.MethodGet, "/user/tokens/"+url.PathEscape(id), nil, &t)
	return t, err
}

// ListTokens returns all of the user's API tokens (without secrets).
func (c *Client) ListTokens(ctx context.Context) ([]Token, error) {
	return getAll[Token](ctx, c, "/user/tokens", url.Values{})
}

// CreateToken creates a token and returns it with its secret Value set.
func (c *Client) CreateToken(ctx context.Context, t Token) (Token, error) {
	var out Token
	_, err := c.do(ctx, http.MethodPost, "/user/tokens", t, &out)
	return out, err
}

// DeleteToken deletes a token. A token may delete itself.
func (c *Client) DeleteToken(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/user/tokens/"+url.PathEscape(id), nil, nil)
	return err
}

// PermissionGroups lists every permission group a token can be granted.
func (c *Client) PermissionGroups(ctx context.Context) ([]PermissionGroup, error) {
	var groups []PermissionGroup
	_, err := c.do(ctx, http.MethodGet, "/user/tokens/permission_groups", nil, &groups)
	return groups, err
}

// Accounts lists the accounts the token can see.
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	return getAll[Account](ctx, c, "/accounts", url.Values{})
}

// ZoneByName looks up a zone by its domain name.
func (c *Client) ZoneByName(ctx context.Context, name string) (Zone, error) {
	var zones []Zone
	q := url.Values{"name": {name}}
	if _, err := c.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil, &zones); err != nil {
		return Zone{}, err
	}
	if len(zones) == 0 {
		return Zone{}, fmt.Errorf("zone %q not found (or the session token cannot read it)", name)
	}
	return zones[0], nil
}
