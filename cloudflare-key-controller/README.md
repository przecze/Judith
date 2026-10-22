# cfkey: Cloudflare Key Controller

Let AI agents on your Mac get the Cloudflare API tokens they need, without
ever giving them your master token. Every key is approved by you, scoped to
exactly what was asked, short-lived, and revoked when your session ends.

```
agent ── cfkey request ──▶ cfkey serve ──▶ Cloudflare API
          (Unix socket)      │ holds a self-destructing session token in memory
                             ├─▶ macOS notification
                             └─▶ dashboard on http://localhost:7787 ◀── you click Approve
```

## How it works

1. **You** run `cfkey serve` and paste your master API token (input hidden).
   - cfkey checks the token and deletes leftover `cfkey-*` tokens from earlier sessions.
   - It creates a **session token**: a copy of your master token's permissions
     that expires after 12h at most. Your master token is then dropped from memory.
   - It prints a private dashboard link.
2. **An agent** asks for a key:
   ```sh
   cfkey request --perm "DNS Write" --zone example.com --ttl 1h \
       --reason "Add TXT record for domain verification"
   ```
   The command blocks until you decide.
3. **You** get a notification. The dashboard shows the exact permissions, zones,
   lifetime, reason, the requesting process chain and its working directory,
   and the raw token policies. You click **Approve** or **Deny**.
4. On approval, cfkey creates exactly that token and prints it to the agent.
5. **When you stop** `cfkey serve` (Ctrl+C, closing the terminal, "End
   session" in the dashboard, or the session expiring), every key issued in
   the session is revoked and the session token deletes itself. If cfkey
   crashes, each token's expiry date still applies, and the next `cfkey serve`
   deletes what is left.

## Commands

| Who | Command | What it does |
|---|---|---|
| you | `cfkey serve` | start a session (`-h` for limits: `--max-ttl`, `--session-ttl`, `--port`, ...) |
| agent | `cfkey request --perm P [--zone Z] [--account A] [--ttl D] [--ip CIDR] --reason R` | wait for approval, print the token (`--json` for IDs/expiry) |
| agent | `cfkey run --perm P ... --reason R -- wrangler deploy` | run a command with `CLOUDFLARE_API_TOKEN` set; revoke the key when it exits |
| agent | `cfkey perms [filter]` | list permission names and which are never granted |
| agent | `cfkey list` / `cfkey revoke ID` / `cfkey status` | see live keys, revoke one, check the session |

`--perm` and `--zone` can be repeated. `--zone '*'` means all zones in the
account. Zone-level permissions need `--zone`; account-level ones apply to the
account (pass `--account` if you have several).

The master token can also be piped in, for example from a password manager:
`op read op://Private/cloudflare/token | cfkey serve`.

## The master token

Create an API token in the Cloudflare dashboard with at least:
- **User → API Tokens → Edit**, so it can create and delete tokens.
- **Zone → Zone → Read** on all zones, so agents can refer to zones by name.
- **Account → Account Settings → Read**, to list accounts.

Agents can only get permissions that your master token could grant.

## Policy (what agents can never get)

Enforced in `internal/policy/policy.go`:
- No permission whose name contains **API Tokens**, **OAuth**, **Memberships**,
  **Billing** or **Account Settings**, and no **user-level** permission. These
  would let an agent mint its own keys or take over the account.
- Every key expires: 1h by default, 24h at most, and never after the session ends.
- A reason is required and is shown to you. Control characters are stripped
  so it cannot fake extra lines.

## Install

```sh
make build         # or: go build -o cfkey .
make install       # copies to /usr/local/bin, owned by root (see SECURITY.md)
make audit         # tests (race detector), go vet, staticcheck, govulncheck
```

Requires Go 1.24+. It has no third-party dependencies.

See [SECURITY.md](SECURITY.md) for the threat model.
