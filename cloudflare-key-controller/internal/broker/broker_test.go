package broker

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfkey/internal/cf"
	"cfkey/internal/cf/cftest"
	"cfkey/internal/peer"
	"cfkey/internal/policy"
)

var (
	groups = []cf.PermissionGroup{
		{ID: "g-dns", Name: "DNS Write", Scopes: []string{policy.ScopeZone}},
		{ID: "g-workers", Name: "Workers Scripts Write", Scopes: []string{policy.ScopeAccount}},
		{ID: "g-tokens", Name: "API Tokens Write", Scopes: []string{policy.ScopeUser}},
	}
	masterPolicies = []cf.Policy{{
		ID: "p1", Effect: "allow",
		Resources:        json.RawMessage(`{"com.cloudflare.api.user.u1":"*"}`),
		PermissionGroups: []cf.PermissionGroup{{ID: "g-tokens", Name: "API Tokens Write"}},
	}}
)

func newFake(t *testing.T) (*cftest.Fake, string) {
	f, master := cftest.New(masterPolicies)
	t.Cleanup(f.Close)
	f.Groups = groups
	f.Accounts = []cf.Account{{ID: "a1", Name: "Main"}}
	f.Zones = []cf.Zone{{ID: "z1", Name: "example.com", Account: cf.Account{ID: "a1", Name: "Main"}}}
	return f, master
}

func start(t *testing.T, f *cftest.Fake, master string) *Broker {
	t.Helper()
	cfg := Config{
		Rules:           policy.DefaultRules,
		SessionTTL:      12 * time.Hour,
		ApprovalTimeout: 5 * time.Second,
		AuditLog:        filepath.Join(t.TempDir(), "audit.log"),
		NewClient:       func(tok string) *cf.Client { return cf.NewWithBaseURL(tok, f.URL) },
		Notify:          func(string, string) {},
	}
	b, _, err := Start(context.Background(), cfg, master)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var dnsSpec = policy.Spec{Permissions: []string{"DNS Write"}, Zones: []string{"example.com"}, TTL: time.Hour, Reason: "add TXT record"}

func TestSessionLifecycle(t *testing.T) {
	f, master := newFake(t)
	f.Add(cf.Token{Name: "cfkey-old-leftover", Policies: masterPolicies})
	f.Add(cf.Token{Name: "unrelated", Policies: masterPolicies})

	b := start(t, f, master)
	if _, ok := f.Token("cfkey-old-leftover"); ok {
		t.Error("leftover cfkey token was not cleaned up")
	}
	if _, ok := f.Token("unrelated"); !ok {
		t.Error("unrelated token was deleted")
	}
	sess, ok := f.Token("cfkey-session-" + b.sessionID)
	if !ok {
		t.Fatal("no session token created")
	}
	if sess.ExpiresOn == "" || len(sess.Policies) != 1 || sess.Policies[0].ID != "" {
		t.Errorf("session token should copy master policies without IDs and expire: %+v", sess)
	}

	r, err := b.Submit(context.Background(), dnsSpec, peer.Info{PID: 42})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = b.Decide(r.ID, true) }()
	issued, err := b.Wait(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.TokenID == "" {
		t.Fatalf("no token issued: %+v", issued)
	}
	key, ok := f.Token("cfkey-" + b.sessionID + "-" + r.ID)
	if !ok {
		t.Fatal("issued key not found")
	}
	if got := string(key.Policies[0].Resources); got != `{"com.cloudflare.api.account.zone.z1":"*"}` {
		t.Errorf("resources = %s", got)
	}
	if key.ExpiresOn == "" {
		t.Error("issued key has no expiry")
	}
	for _, snap := range b.Snapshot() {
		if strings.Contains(mustJSON(t, snap), issued.Token) {
			t.Error("broker state contains the secret")
		}
	}

	rep := b.Shutdown(context.Background())
	if len(rep.Revoked) != 1 || !rep.SessionTokenDeleted || len(rep.Errors) > 0 {
		t.Errorf("shutdown report: %+v", rep)
	}
	for _, tok := range f.Tokens() {
		if strings.HasPrefix(tok.Name, NamePrefix) {
			t.Errorf("token %s survived shutdown", tok.Name)
		}
	}
	if _, ok := f.Token("my master"); !ok {
		t.Error("master token must not be deleted")
	}
}

func TestDenyAndForbidden(t *testing.T) {
	f, master := newFake(t)
	b := start(t, f, master)
	defer b.Shutdown(context.Background())

	if _, err := b.Submit(context.Background(), policy.Spec{Permissions: []string{"API Tokens Write"}, Reason: "x"}, peer.Info{}); err == nil {
		t.Error("API Tokens Write must be refused")
	}
	r, err := b.Submit(context.Background(), dnsSpec, peer.Info{})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = b.Decide(r.ID, false) }()
	if _, err := b.Wait(context.Background(), r); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denial, got %v", err)
	}
	if len(f.Tokens()) != 2 { // master + session
		t.Errorf("a denied request created a token")
	}
}

func TestAgentDisconnectCancels(t *testing.T) {
	f, master := newFake(t)
	b := start(t, f, master)
	defer b.Shutdown(context.Background())
	r, err := b.Submit(context.Background(), dnsSpec, peer.Info{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Wait(ctx, r); err == nil {
		t.Fatal("expected cancellation")
	}
	if err := b.Decide(r.ID, true); err == nil {
		t.Error("approving a canceled request should fail")
	}
}

func TestSocketRoundTrip(t *testing.T) {
	f, master := newFake(t)
	b := start(t, f, master)
	defer b.Shutdown(context.Background())

	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = b.Serve(ln) }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	spec := dnsSpec
	_ = json.NewEncoder(c).Encode(Message{Op: "request", Spec: &spec})
	dec := json.NewDecoder(c)
	var pending Reply
	if err := dec.Decode(&pending); err != nil || pending.Type != "pending" {
		t.Fatalf("pending reply: %+v %v", pending, err)
	}
	snap := b.Snapshot()
	if snap[0].Peer.PID == 0 {
		t.Error("peer PID not recorded")
	}
	if err := b.Decide(pending.RequestID, true); err != nil {
		t.Fatal(err)
	}
	var done Reply
	if err := dec.Decode(&done); err != nil || done.Type != "issued" || done.Issued.Token == "" {
		t.Fatalf("issued reply: %+v %v", done, err)
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
