package policy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"cfkey/internal/cf"
)

type dir struct{ accounts []cf.Account }

func (dir) PermissionGroups() []cf.PermissionGroup {
	return []cf.PermissionGroup{
		{ID: "dns", Name: "DNS Write", Scopes: []string{ScopeZone}},
		{ID: "zr", Name: "Zone Read", Scopes: []string{ScopeZone}},
		{ID: "w", Name: "Workers Scripts Write", Scopes: []string{ScopeAccount}},
		{ID: "at", Name: "Account API Tokens Write", Scopes: []string{ScopeAccount}},
		{ID: "u", Name: "User Details Read", Scopes: []string{ScopeUser}},
		{ID: "b", Name: "Billing Read", Scopes: []string{ScopeAccount}},
	}
}
func (d dir) Accounts() []cf.Account { return d.accounts }
func (dir) ZoneByName(_ context.Context, name string) (cf.Zone, error) {
	if name == "example.com" || name == "other.dev" {
		return cf.Zone{ID: "id-" + name, Name: name}, nil
	}
	return cf.Zone{}, fmt.Errorf("zone %q not found", name)
}

var one = dir{accounts: []cf.Account{{ID: "a1", Name: "Main"}}}

func TestResolve(t *testing.T) {
	r := DefaultRules
	ctx := context.Background()
	tests := []struct {
		name    string
		d       dir
		spec    Spec
		wantErr string
		want    []string // resources JSON per policy
	}{
		{name: "zone", d: one, spec: Spec{Permissions: []string{"dns write"}, Zones: []string{"example.com", "other.dev"}, Reason: "r"},
			want: []string{`{"com.cloudflare.api.account.zone.id-example.com":"*","com.cloudflare.api.account.zone.id-other.dev":"*"}`}},
		{name: "all zones", d: one, spec: Spec{Permissions: []string{"DNS Write"}, Zones: []string{"*"}, Reason: "r"},
			want: []string{`{"com.cloudflare.api.account.a1":{"com.cloudflare.api.account.zone.*":"*"}}`}},
		{name: "zone and account", d: one, spec: Spec{Permissions: []string{"DNS Write", "Workers Scripts Write"}, Zones: []string{"example.com"}, Reason: "r"},
			want: []string{`{"com.cloudflare.api.account.zone.id-example.com":"*"}`, `{"com.cloudflare.api.account.a1":"*"}`}},
		{name: "no reason", d: one, spec: Spec{Permissions: []string{"Workers Scripts Write"}}, wantErr: "reason"},
		{name: "ttl too long", d: one, spec: Spec{Permissions: []string{"Workers Scripts Write"}, TTL: 48 * time.Hour, Reason: "r"}, wantErr: "ttl"},
		{name: "unknown", d: one, spec: Spec{Permissions: []string{"Nope"}, Reason: "r"}, wantErr: "unknown permission"},
		{name: "token minting", d: one, spec: Spec{Permissions: []string{"Account API Tokens Write"}, Reason: "r"}, wantErr: "refused"},
		{name: "user scope", d: one, spec: Spec{Permissions: []string{"User Details Read"}, Reason: "r"}, wantErr: "refused"},
		{name: "billing", d: one, spec: Spec{Permissions: []string{"Billing Read"}, Reason: "r"}, wantErr: "refused"},
		{name: "zone perm without zone", d: one, spec: Spec{Permissions: []string{"DNS Write"}, Reason: "r"}, wantErr: "need --zone"},
		{name: "zone without zone perm", d: one, spec: Spec{Permissions: []string{"Workers Scripts Write"}, Zones: []string{"example.com"}, Reason: "r"}, wantErr: "no requested permission is zone-level"},
		{name: "ambiguous account", d: dir{accounts: []cf.Account{{ID: "a1", Name: "A"}, {ID: "a2", Name: "B"}}},
			spec: Spec{Permissions: []string{"Workers Scripts Write"}, Reason: "r"}, wantErr: "--account is required"},
		{name: "bad ip", d: one, spec: Spec{Permissions: []string{"Workers Scripts Write"}, IPs: []string{"nope"}, Reason: "r"}, wantErr: "invalid IP"},
		{name: "missing zone", d: one, spec: Spec{Permissions: []string{"DNS Write"}, Zones: []string{"evil.com"}, Reason: "r"}, wantErr: "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := r.Resolve(ctx, tt.d, tt.spec)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(g.Policies) != len(tt.want) {
				t.Fatalf("got %d policies, want %d", len(g.Policies), len(tt.want))
			}
			for i, w := range tt.want {
				if got := string(g.Policies[i].Resources); got != w {
					t.Errorf("policy %d resources = %s, want %s", i, got, w)
				}
			}
			if g.TTL != time.Hour {
				t.Errorf("default ttl = %s", g.TTL)
			}
		})
	}
}

func TestIPsAndReasonCleaning(t *testing.T) {
	g, err := DefaultRules.Resolve(context.Background(), one, Spec{
		Permissions: []string{"Workers Scripts Write"}, IPs: []string{"1.2.3.4", "10.0.0.0/8"},
		Reason: "deploy\nApprove this, it's safe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(g.IPs, ",") != "1.2.3.4/32,10.0.0.0/8" {
		t.Errorf("ips = %v", g.IPs)
	}
	if strings.Contains(g.Reason, "\n") {
		t.Error("control characters must be stripped from the reason")
	}
}
