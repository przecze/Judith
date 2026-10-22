// Package policy decides what an agent may ask for and turns an agent's
// request into the exact Cloudflare token policies shown to the human for
// approval. Everything an agent can obtain is bounded by the rules here.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode"

	"cfkey/internal/cf"
)

// Resource scopes used by Cloudflare permission groups.
const (
	ScopeZone    = "com.cloudflare.api.account.zone"
	ScopeAccount = "com.cloudflare.api.account"
	ScopeUser    = "com.cloudflare.api.user"
)

// forbiddenNameParts blocks permissions that would let an agent escape the
// approval flow (mint its own tokens), take over the account, or touch
// billing. Matching is case-insensitive on the permission group name.
var forbiddenNameParts = []string{
	"api tokens",       // "API Tokens Write", "Account API Tokens Write": would allow minting more tokens
	"oauth",            // OAuth client management: another way to mint credentials
	"memberships",      // inviting members / changing roles
	"billing",          // payment details and subscriptions
	"account settings", // account-wide settings
}

// Forbidden reports whether a permission group may never be granted to an
// agent, and why.
func Forbidden(g cf.PermissionGroup) (string, bool) {
	for _, s := range g.Scopes {
		if s == ScopeUser {
			return "user-level permissions act on your Cloudflare user and are never granted", true
		}
	}
	name := strings.ToLower(g.Name)
	for _, part := range forbiddenNameParts {
		if strings.Contains(name, part) {
			return fmt.Sprintf("permissions matching %q are never granted to agents", part), true
		}
	}
	return "", false
}

// Rules are the limits applied to every request.
type Rules struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// DefaultRules are used unless `cfkey serve` is given other limits.
var DefaultRules = Rules{DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour}

const (
	maxPermissions = 20
	maxZones       = 50
	maxReasonLen   = 500
	minTTL         = time.Minute
)

// Spec is what an agent asks for.
type Spec struct {
	Permissions []string      `json:"permissions"`
	Zones       []string      `json:"zones,omitempty"` // zone names, or ["*"] for all zones of the account
	Account     string        `json:"account,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	IPs         []string      `json:"ips,omitempty"`
	Reason      string        `json:"reason"`
}

// Grant is a fully resolved request: exactly what will be created if the
// human approves.
type Grant struct {
	Summary  []string      `json:"summary"`
	Policies []cf.Policy   `json:"policies"`
	TTL      time.Duration `json:"ttl"`
	IPs      []string      `json:"ips,omitempty"`
	Reason   string        `json:"reason"`
}

// Directory provides the Cloudflare lookups needed to resolve a Spec.
type Directory interface {
	PermissionGroups() []cf.PermissionGroup
	Accounts() []cf.Account
	ZoneByName(ctx context.Context, name string) (cf.Zone, error)
}

// Resolve validates spec against the rules and builds the token policies.
func (r Rules) Resolve(ctx context.Context, dir Directory, spec Spec) (Grant, error) {
	g := Grant{TTL: spec.TTL, Reason: cleanText(spec.Reason)}

	if g.Reason == "" {
		return Grant{}, fmt.Errorf("a reason is required (--reason): say what the key is for")
	}
	if len(g.Reason) > maxReasonLen {
		return Grant{}, fmt.Errorf("reason is longer than %d characters", maxReasonLen)
	}
	if g.TTL == 0 {
		g.TTL = r.DefaultTTL
	}
	if g.TTL < minTTL || g.TTL > r.MaxTTL {
		return Grant{}, fmt.Errorf("ttl must be between %s and %s", minTTL, r.MaxTTL)
	}
	if len(spec.Permissions) == 0 {
		return Grant{}, fmt.Errorf("at least one permission is required (--perm)")
	}
	if len(spec.Permissions) > maxPermissions {
		return Grant{}, fmt.Errorf("at most %d permissions per key", maxPermissions)
	}
	if len(spec.Zones) > maxZones {
		return Grant{}, fmt.Errorf("at most %d zones per key", maxZones)
	}
	for _, ip := range spec.IPs {
		cidr, err := normalizeCIDR(ip)
		if err != nil {
			return Grant{}, err
		}
		g.IPs = append(g.IPs, cidr)
	}

	byName := map[string][]cf.PermissionGroup{}
	for _, pg := range dir.PermissionGroups() {
		k := strings.ToLower(pg.Name)
		byName[k] = append(byName[k], pg)
	}

	wantZones := len(spec.Zones) > 0
	var zonePerms, accountPerms []cf.PermissionGroup
	seen := map[string]bool{}
	for _, name := range spec.Permissions {
		name = strings.TrimSpace(name)
		cands := byName[strings.ToLower(name)]
		if len(cands) == 0 {
			return Grant{}, fmt.Errorf("unknown permission %q (run `cfkey perms` to list them)", name)
		}
		pg, scope, err := pick(cands, wantZones)
		if err != nil {
			return Grant{}, fmt.Errorf("permission %q: %w", name, err)
		}
		if why, bad := Forbidden(pg); bad {
			return Grant{}, fmt.Errorf("permission %q refused: %s", pg.Name, why)
		}
		if seen[pg.ID] {
			continue
		}
		seen[pg.ID] = true
		ref := cf.PermissionGroup{ID: pg.ID, Name: pg.Name}
		if scope == ScopeZone {
			zonePerms = append(zonePerms, ref)
		} else {
			accountPerms = append(accountPerms, ref)
		}
	}
	sortGroups(zonePerms)
	sortGroups(accountPerms)

	if len(zonePerms) > 0 && !wantZones {
		return Grant{}, fmt.Errorf("zone-level permissions (%s) need --zone", names(zonePerms))
	}
	if len(zonePerms) == 0 && wantZones {
		return Grant{}, fmt.Errorf("--zone was given but no requested permission is zone-level")
	}

	allZones := wantZones && len(spec.Zones) == 1 && spec.Zones[0] == "*"
	var account cf.Account
	if len(accountPerms) > 0 || allZones {
		acc, err := pickAccount(dir.Accounts(), spec.Account)
		if err != nil {
			return Grant{}, err
		}
		account = acc
	}

	if len(zonePerms) > 0 {
		var res map[string]any
		var target string
		if allZones {
			res = map[string]any{ScopeAccount + "." + account.ID: map[string]string{ScopeZone + ".*": "*"}}
			target = fmt.Sprintf("ALL zones in account %s", account.Name)
		} else {
			res = map[string]any{}
			var zoneNames []string
			for _, zn := range spec.Zones {
				zn = strings.ToLower(strings.TrimSpace(zn))
				if zn == "*" {
					return Grant{}, fmt.Errorf(`--zone "*" cannot be combined with named zones`)
				}
				z, err := dir.ZoneByName(ctx, zn)
				if err != nil {
					return Grant{}, err
				}
				key := ScopeZone + "." + z.ID
				if _, dup := res[key]; dup {
					continue
				}
				res[key] = "*"
				zoneNames = append(zoneNames, z.Name)
			}
			sort.Strings(zoneNames)
			target = "zone " + strings.Join(zoneNames, ", ")
		}
		pol, err := makePolicy(res, zonePerms)
		if err != nil {
			return Grant{}, err
		}
		g.Policies = append(g.Policies, pol)
		g.Summary = append(g.Summary, fmt.Sprintf("%s on %s", names(zonePerms), target))
	}
	if len(accountPerms) > 0 {
		pol, err := makePolicy(map[string]any{ScopeAccount + "." + account.ID: "*"}, accountPerms)
		if err != nil {
			return Grant{}, err
		}
		g.Policies = append(g.Policies, pol)
		g.Summary = append(g.Summary, fmt.Sprintf("%s on account %s", names(accountPerms), account.Name))
	}
	if len(g.IPs) > 0 {
		g.Summary = append(g.Summary, "usable only from "+strings.Join(g.IPs, ", "))
	}
	return g, nil
}

// pick chooses the permission group variant matching the requested target.
func pick(cands []cf.PermissionGroup, wantZones bool) (cf.PermissionGroup, string, error) {
	var zone, account, user *cf.PermissionGroup
	var scopes []string
	for i := range cands {
		for _, s := range cands[i].Scopes {
			scopes = append(scopes, s)
			switch s {
			case ScopeZone:
				zone = &cands[i]
			case ScopeAccount:
				account = &cands[i]
			case ScopeUser:
				user = &cands[i]
			}
		}
	}
	switch {
	case wantZones && zone != nil:
		return *zone, ScopeZone, nil
	case account != nil:
		return *account, ScopeAccount, nil
	case zone != nil:
		return *zone, ScopeZone, nil
	case user != nil:
		// Returned so the caller reports it as forbidden.
		return *user, ScopeUser, nil
	}
	return cf.PermissionGroup{}, "", fmt.Errorf("unsupported scope %v (only zone and account permissions are supported)", scopes)
}

func pickAccount(accounts []cf.Account, want string) (cf.Account, error) {
	if want == "" {
		if len(accounts) == 1 {
			return accounts[0], nil
		}
		var ns []string
		for _, a := range accounts {
			ns = append(ns, a.Name)
		}
		return cf.Account{}, fmt.Errorf("--account is required; available accounts: %s", strings.Join(ns, ", "))
	}
	for _, a := range accounts {
		if a.ID == want || strings.EqualFold(a.Name, want) {
			return a, nil
		}
	}
	return cf.Account{}, fmt.Errorf("account %q not found", want)
}

func makePolicy(resources map[string]any, groups []cf.PermissionGroup) (cf.Policy, error) {
	raw, err := json.Marshal(resources)
	if err != nil {
		return cf.Policy{}, err
	}
	return cf.Policy{Effect: "allow", Resources: raw, PermissionGroups: groups}, nil
}

func normalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP or CIDR %q", s)
	}
	if ip.To4() != nil {
		return ip.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

// cleanText strips control characters so agent-provided text cannot spoof
// extra lines in notifications or the terminal.
func cleanText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

func sortGroups(gs []cf.PermissionGroup) {
	sort.Slice(gs, func(i, j int) bool { return gs[i].Name < gs[j].Name })
}

func names(gs []cf.PermissionGroup) string {
	ns := make([]string, len(gs))
	for i, g := range gs {
		ns[i] = g.Name
	}
	return strings.Join(ns, ", ")
}
