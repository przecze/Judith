// Package broker holds the session token in memory, queues agent requests
// for human approval, mints approved keys and revokes everything when the
// session ends.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cfkey/internal/cf"
	"cfkey/internal/notify"
	"cfkey/internal/peer"
	"cfkey/internal/policy"
)

// NamePrefix marks every token cfkey creates, so leftovers from a crashed
// session can be found and deleted.
const NamePrefix = "cfkey-"

// Config controls a broker session.
type Config struct {
	Rules           policy.Rules
	SessionTTL      time.Duration // lifetime of the session token
	ApprovalTimeout time.Duration // how long a request waits for a decision
	// NoSessionToken uses the master token directly instead of minting a
	// self-destructing session copy. Agent keys are still revoked on exit.
	NoSessionToken bool
	AuditLog       string // path of the JSON-lines audit log; "" disables it
	// NewClient builds Cloudflare clients; tests point it at a fake API.
	NewClient func(token string) *cf.Client
	// Notify shows a desktop notification; defaults to notify.Send.
	Notify func(title, message string)
}

// Status is the lifecycle state of a request.
type Status string

const (
	StatusRejected Status = "rejected" // failed policy checks, never shown for approval
	StatusPending  Status = "pending"
	StatusDenied   Status = "denied"
	StatusTimedOut Status = "timed_out"
	StatusCanceled Status = "canceled" // the agent went away before a decision
	StatusApproved Status = "approved" // approved, key being created
	StatusFailed   Status = "failed"   // approved, but Cloudflare refused to create the key
	StatusIssued   Status = "issued"
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked"
)

// Request is one agent request and, once issued, the key it produced.
// The key's secret is never stored here.
type Request struct {
	ID        string       `json:"id"`
	Created   time.Time    `json:"created"`
	Spec      policy.Spec  `json:"spec"`
	Grant     policy.Grant `json:"grant"`
	Peer      peer.Info    `json:"peer"`
	Status    Status       `json:"status"`
	Decided   time.Time    `json:"decided,omitempty"`
	Error     string       `json:"error,omitempty"`
	TokenID   string       `json:"token_id,omitempty"`
	ExpiresOn time.Time    `json:"expires_on,omitempty"`
	RevokedAt time.Time    `json:"revoked_at,omitempty"`

	decision chan bool
}

// Issued is what an agent receives for an approved request.
type Issued struct {
	RequestID string    `json:"request_id"`
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresOn time.Time `json:"expires_on"`
	Summary   []string  `json:"summary"`
}

// Broker is a running session.
type Broker struct {
	cfg            Config
	sessionID      string
	client         *cf.Client // session token (or master with NoSessionToken)
	sessionTokenID string     // deleted on shutdown; "" with NoSessionToken
	started        time.Time
	expires        time.Time
	groups         []cf.PermissionGroup
	accounts       []cf.Account

	mu       sync.Mutex
	requests map[string]*Request
	order    []string
	closing  bool
	minting  sync.WaitGroup // approved requests whose key is being created
}

// StartReport says what happened while starting a session.
type StartReport struct {
	MasterTokenID   string
	CleanedUp       []string // names of leftover cfkey tokens deleted
	SessionTokenID  string
	SessionExpires  time.Time
	PermissionCount int
	Accounts        []cf.Account
}

// Start verifies the master token, deletes leftovers of earlier sessions,
// mints the session token and loads permission groups and accounts. The
// master token is not retained once Start returns.
func Start(ctx context.Context, cfg Config, masterToken string) (*Broker, StartReport, error) {
	if cfg.NewClient == nil {
		cfg.NewClient = cf.New
	}
	if cfg.Notify == nil {
		cfg.Notify = notify.Send
	}
	var rep StartReport
	master := cfg.NewClient(strings.TrimSpace(masterToken))
	defer master.Forget()

	self, err := master.VerifyToken(ctx)
	if err != nil {
		return nil, rep, fmt.Errorf("verifying master token: %w", err)
	}
	if self.Status != "active" {
		return nil, rep, fmt.Errorf("master token status is %q, not active", self.Status)
	}
	rep.MasterTokenID = self.ID
	masterTok, err := master.GetToken(ctx, self.ID)
	if err != nil {
		return nil, rep, fmt.Errorf("reading master token (it needs the \"API Tokens Write\" permission): %w", err)
	}

	tokens, err := master.ListTokens(ctx)
	if err != nil {
		return nil, rep, fmt.Errorf("listing tokens: %w", err)
	}
	for _, t := range tokens {
		if t.ID == self.ID || !strings.HasPrefix(t.Name, NamePrefix) {
			continue
		}
		if err := master.DeleteToken(ctx, t.ID); err != nil {
			return nil, rep, fmt.Errorf("deleting leftover token %s: %w", t.Name, err)
		}
		rep.CleanedUp = append(rep.CleanedUp, t.Name)
	}

	b := &Broker{
		cfg:       cfg,
		sessionID: randomHex(3),
		started:   time.Now(),
		requests:  map[string]*Request{},
	}
	b.expires = b.started.Add(cfg.SessionTTL)
	if masterTok.ExpiresOn != "" {
		if t, err := time.Parse(time.RFC3339, masterTok.ExpiresOn); err == nil && t.Before(b.expires) {
			b.expires = t
		}
	}

	if cfg.NoSessionToken {
		b.client = cfg.NewClient(strings.TrimSpace(masterToken))
	} else {
		// The session token is a copy of the master token's powers with a
		// hard expiry, so a crash can never leave it valid for long.
		policies := make([]cf.Policy, len(masterTok.Policies))
		for i, p := range masterTok.Policies {
			p.ID = ""
			policies[i] = p
		}
		created, err := master.CreateToken(ctx, cf.Token{
			Name:      NamePrefix + "session-" + b.sessionID,
			Policies:  policies,
			Condition: masterTok.Condition,
			ExpiresOn: cf.FormatTime(b.expires),
		})
		if err != nil {
			return nil, rep, fmt.Errorf("creating session token: %w", err)
		}
		b.sessionTokenID = created.ID
		b.client = cfg.NewClient(created.Value)
		if _, err := b.client.VerifyToken(ctx); err != nil {
			_ = master.DeleteToken(ctx, created.ID)
			return nil, rep, fmt.Errorf("verifying session token: %w", err)
		}
	}
	rep.SessionTokenID = b.sessionTokenID
	rep.SessionExpires = b.expires

	fail := func(err error) (*Broker, StartReport, error) {
		b.Shutdown(context.Background())
		return nil, rep, err
	}
	if b.groups, err = b.client.PermissionGroups(ctx); err != nil {
		return fail(fmt.Errorf("loading permission groups: %w", err))
	}
	if b.accounts, err = b.client.Accounts(ctx); err != nil {
		return fail(fmt.Errorf("loading accounts: %w", err))
	}
	rep.PermissionCount = len(b.groups)
	rep.Accounts = b.accounts
	b.audit("session_started", map[string]any{"session": b.sessionID, "expires": b.expires})
	return b, rep, nil
}

// directory adapts the broker to policy.Directory.
type directory struct{ b *Broker }

func (d directory) PermissionGroups() []cf.PermissionGroup { return d.b.groups }
func (d directory) Accounts() []cf.Account                 { return d.b.accounts }
func (d directory) ZoneByName(ctx context.Context, name string) (cf.Zone, error) {
	return d.b.client.ZoneByName(ctx, name)
}

// ErrClosing is returned once the session is shutting down.
var ErrClosing = errors.New("the cfkey session is shutting down")

// Submit validates a request and queues it for approval. Requests that fail
// policy checks are recorded as rejected and returned with an error.
func (b *Broker) Submit(ctx context.Context, spec policy.Spec, from peer.Info) (*Request, error) {
	r := &Request{
		ID:       randomHex(4),
		Created:  time.Now(),
		Spec:     spec,
		Peer:     from,
		decision: make(chan bool, 1),
	}
	grant, err := b.cfg.Rules.Resolve(ctx, directory{b}, spec)
	if err == nil && time.Now().Add(grant.TTL).After(b.expires) {
		err = fmt.Errorf("the session ends at %s; ask for a shorter ttl", b.expires.Format(time.Kitchen))
	}
	r.Grant = grant

	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return nil, ErrClosing
	}
	if err != nil {
		r.Status, r.Error, r.Decided = StatusRejected, err.Error(), time.Now()
	} else {
		r.Status = StatusPending
	}
	b.requests[r.ID] = r
	b.order = append(b.order, r.ID)
	b.mu.Unlock()

	if err != nil {
		b.auditRequest("request_rejected", r)
		return r, err
	}
	b.auditRequest("request_pending", r)
	b.cfg.Notify("Cloudflare key requested", strings.Join(grant.Summary, " · ")+"\nReason: "+grant.Reason)
	return r, nil
}

// Wait blocks until the request is decided, the agent disconnects (ctx is
// canceled) or the approval times out, and mints the key if approved.
func (b *Broker) Wait(ctx context.Context, r *Request) (Issued, error) {
	timer := time.NewTimer(b.cfg.ApprovalTimeout)
	defer timer.Stop()
	var approved bool
	select {
	case approved = <-r.decision:
	case <-ctx.Done():
		b.finish(r, StatusCanceled, "the requesting agent disconnected")
		return Issued{}, ctx.Err()
	case <-timer.C:
		b.finish(r, StatusTimedOut, "no decision within "+b.cfg.ApprovalTimeout.String())
		return Issued{}, fmt.Errorf("request %s timed out waiting for approval", r.ID)
	}
	if !approved {
		return Issued{}, fmt.Errorf("request %s was denied", r.ID)
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return Issued{}, ErrClosing
	}
	b.minting.Add(1)
	b.mu.Unlock()
	defer b.minting.Done()
	if ctx.Err() != nil {
		b.finish(r, StatusCanceled, "the requesting agent disconnected")
		return Issued{}, ctx.Err()
	}

	expires := time.Now().Add(r.Grant.TTL)
	tok := cf.Token{
		Name:      fmt.Sprintf("%s%s-%s", NamePrefix, b.sessionID, r.ID),
		Policies:  r.Grant.Policies,
		ExpiresOn: cf.FormatTime(expires),
	}
	if len(r.Grant.IPs) > 0 {
		tok.Condition = &cf.Condition{RequestIP: &cf.IPCondition{In: r.Grant.IPs}}
	}
	// Mint with a fresh context: the agent may disconnect meanwhile, and the
	// token must then still be recorded so it can be revoked.
	mctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := b.client.CreateToken(mctx, tok)
	if err != nil {
		b.finish(r, StatusFailed, err.Error())
		return Issued{}, fmt.Errorf("creating key: %w", err)
	}

	b.mu.Lock()
	r.TokenID = created.ID
	r.ExpiresOn = expires
	r.Status = StatusIssued
	b.mu.Unlock()
	b.auditRequest("key_issued", r)

	if ctx.Err() != nil {
		// The agent left while the key was minted: nobody will use it.
		_ = b.Revoke(mctx, r.ID)
		return Issued{}, fmt.Errorf("request %s was canceled", r.ID)
	}
	return Issued{
		RequestID: r.ID,
		TokenID:   created.ID,
		Token:     created.Value,
		ExpiresOn: expires,
		Summary:   r.Grant.Summary,
	}, nil
}

// Decide records the human's decision on a pending request.
func (b *Broker) Decide(id string, approve bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.requests[id]
	if !ok {
		return fmt.Errorf("no request %q", id)
	}
	if r.Status != StatusPending {
		return fmt.Errorf("request %s is %s, not pending", id, r.Status)
	}
	r.Decided = time.Now()
	event := "request_denied"
	r.Status = StatusDenied
	if approve {
		event = "request_approved"
		r.Status = StatusApproved
	}
	r.decision <- approve
	snapshot := *r
	go b.audit(event, snapshot)
	return nil
}

// Revoke deletes the key issued for a request (by request or token ID).
func (b *Broker) Revoke(ctx context.Context, id string) error {
	b.mu.Lock()
	r := b.lookupLocked(id)
	if r == nil || r.TokenID == "" {
		b.mu.Unlock()
		return fmt.Errorf("no issued key %q", id)
	}
	if r.Status == StatusRevoked {
		b.mu.Unlock()
		return nil
	}
	tokenID := r.TokenID
	b.mu.Unlock()

	if err := b.client.DeleteToken(ctx, tokenID); err != nil {
		return fmt.Errorf("revoking key %s: %w", tokenID, err)
	}
	b.finish(r, StatusRevoked, "")
	return nil
}

func (b *Broker) lookupLocked(id string) *Request {
	if r, ok := b.requests[id]; ok {
		return r
	}
	for _, r := range b.requests {
		if r.TokenID != "" && r.TokenID == id {
			return r
		}
	}
	return nil
}

func (b *Broker) finish(r *Request, s Status, msg string) {
	b.mu.Lock()
	r.Status = s
	r.Error = msg
	if s == StatusRevoked {
		r.RevokedAt = time.Now()
	} else if r.Decided.IsZero() {
		r.Decided = time.Now()
	}
	b.mu.Unlock()
	b.auditRequest("request_"+string(s), r)
}

// auditRequest logs a consistent copy of r.
func (b *Broker) auditRequest(event string, r *Request) {
	b.mu.Lock()
	snapshot := *r
	b.mu.Unlock()
	b.audit(event, snapshot)
}

// ShutdownReport says what was cleaned up when the session ended.
type ShutdownReport struct {
	Revoked             []string
	Errors              []string
	SessionTokenDeleted bool
}

// Shutdown denies pending requests, revokes every live key issued in this
// session and finally makes the session token delete itself.
func (b *Broker) Shutdown(ctx context.Context) ShutdownReport {
	var rep ShutdownReport
	b.mu.Lock()
	b.closing = true
	for _, r := range b.requests {
		if r.Status == StatusPending {
			r.Status, r.Decided = StatusDenied, time.Now()
			r.Error = "session ended"
			r.decision <- false
		}
	}
	b.mu.Unlock()

	// Let keys that are being created right now land, so they get revoked.
	b.minting.Wait()

	b.mu.Lock()
	var live []*Request
	for _, r := range b.requests {
		if r.TokenID != "" && r.Status != StatusRevoked {
			live = append(live, r)
		}
	}
	b.mu.Unlock()

	for _, r := range live {
		if !r.ExpiresOn.IsZero() && time.Now().After(r.ExpiresOn) {
			continue // already dead; deleting is harmless but unnecessary
		}
		if err := b.Revoke(ctx, r.ID); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		} else {
			rep.Revoked = append(rep.Revoked, r.TokenID)
		}
	}
	if b.sessionTokenID != "" {
		if err := b.client.DeleteToken(ctx, b.sessionTokenID); err != nil {
			rep.Errors = append(rep.Errors, "deleting session token: "+err.Error())
		} else {
			rep.SessionTokenDeleted = true
		}
	}
	b.client.Forget()
	b.audit("session_ended", rep)
	return rep
}

// Snapshot returns copies of all requests, newest first, with expired keys
// marked as such.
func (b *Broker) Snapshot() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	out := make([]Request, 0, len(b.order))
	for i := len(b.order) - 1; i >= 0; i-- {
		r := *b.requests[b.order[i]]
		r.decision = nil
		if r.Status == StatusIssued && r.TokenID != "" && now.After(r.ExpiresOn) {
			r.Status = StatusExpired
		}
		out = append(out, r)
	}
	return out
}

// SessionInfo describes the running session.
type SessionInfo struct {
	ID           string    `json:"id"`
	Started      time.Time `json:"started"`
	Expires      time.Time `json:"expires"`
	SessionToken bool      `json:"session_token"`
	MaxTTL       string    `json:"max_ttl"`
}

// Session returns information about the running session.
func (b *Broker) Session() SessionInfo {
	return SessionInfo{
		ID:           b.sessionID,
		Started:      b.started,
		Expires:      b.expires,
		SessionToken: b.sessionTokenID != "",
		MaxTTL:       b.cfg.Rules.MaxTTL.String(),
	}
}

// Permission is a grantable (or forbidden) permission, for listing.
type Permission struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Forbidden string `json:"forbidden,omitempty"`
}

// Permissions lists permission groups with their scope and policy verdict.
func (b *Broker) Permissions() []Permission {
	var out []Permission
	for _, g := range b.groups {
		p := Permission{Name: g.Name, Scope: strings.Join(g.Scopes, ",")}
		switch {
		case contains(g.Scopes, policy.ScopeZone):
			p.Scope = "zone"
		case contains(g.Scopes, policy.ScopeAccount):
			p.Scope = "account"
		case contains(g.Scopes, policy.ScopeUser):
			p.Scope = "user"
		}
		if why, bad := policy.Forbidden(g); bad {
			p.Forbidden = why
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// audit appends an event to the audit log. It never contains secrets.
func (b *Broker) audit(event string, data any) {
	if b.cfg.AuditLog == "" {
		return
	}
	line, err := json.Marshal(map[string]any{"time": time.Now().UTC(), "event": event, "data": data})
	if err != nil {
		return
	}
	f, err := os.OpenFile(b.cfg.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
