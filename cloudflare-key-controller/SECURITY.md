# Security model

## Goal

Agents running as **your macOS user** can use Cloudflare with keys you
approve, but can never get the master token or approve keys themselves.

## What protects what

| Asset | Protection |
|---|---|
| Master token | Typed or piped into `cfkey serve` only. Never written to disk, the environment or process arguments. It is used once to create the session token and then dropped. |
| Session token | Lives only in the memory of `cfkey serve`. It expires within `--session-ttl` (12h), and it deletes itself on a clean exit. |
| Agent keys | Created only after your approval, exactly as displayed, and always with an expiry. Revoked when the session ends. The secret is returned once to the requesting agent and never stored or logged. |
| Approval | Only through the dashboard API, which requires a 256-bit secret. The secret travels in the URL **fragment**, which is never sent over the network, and is kept in origin-scoped `localStorage`. It is sent as a header, so cross-site requests (CSRF) cannot carry it. The server checks the `Host` header (against DNS rebinding) and sets a strict CSP; all agent text is rendered with `textContent`. |
| Agent → service | Unix socket in `~/.cfkey` (mode 0700/0600). Messages are limited in size. The requester's PID comes from the kernel (`LOCAL_PEERPID`/`SO_PEERCRED`). |
| Notifications | Agent text is passed to `osascript` as arguments, never spliced into script source. |
| Cloudflare endpoint | Hard-coded. It can't be overridden from the environment, so a tampered shell profile cannot redirect the master token. |

## Known limits (same-user threats)

Agents run as you, so some attacks remain possible. Mitigate them as noted:

1. **Swapping the binary.** An agent could replace `cfkey`, or put an alias
   in your shell profile, to capture the master token the next time you
   type it. Install with `make install`, which puts a root-owned binary in
   `/usr/local/bin`, and start it as `/usr/local/bin/cfkey serve`. Better
   still, pipe the token from a password manager that requires Touch ID.
2. **Clicking Approve for you.** An app with macOS Accessibility permission
   can click buttons in your browser. Don't grant Accessibility to terminals
   or agent apps. Planned: requiring Touch ID (passkey) for each approval.
3. **Reading the dashboard secret.** It is shown in your terminal and stored
   in your browser's localStorage. An agent able to read your terminal
   scrollback or browser profile could approve requests itself.
4. **Reading process memory.** macOS blocks attaching to another process
   without admin approval or debugger entitlements. Go cannot guarantee that
   secrets are wiped from memory.
5. **Spoofed requester details.** Process names and working directories are
   chosen by the process itself. Judge each request by its permissions and
   reason, not only by who claims to ask.
6. **Ending the session early.** Any agent can kill `cfkey serve`. That only
   revokes keys; it cannot reveal anything. The session token then expires
   on its own, and the next `serve` deletes it.
7. **Approved keys are bearer tokens.** Once you approve a key, the agent
   holds it until it expires or is revoked. Use short TTLs and `--ip`, and
   prefer `cfkey run`, which revokes the key as soon as the command exits.

## Reviewing changes

Run `make audit`. The code is split so that each security decision lives in
one place:
- `internal/policy`: what may be granted
- `internal/broker`: session token lifecycle, approval state machine, revocation
- `internal/dashboard`: human approval surface and its authentication
- `internal/cf`: the only code that talks to Cloudflare
