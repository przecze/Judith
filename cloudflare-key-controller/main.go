// Command cfkey lets agents request short-lived Cloudflare API tokens that a
// human approves, without the agents ever seeing the master token.
//
//	cfkey serve                         start a session (human)
//	cfkey request --perm ... --reason   ask for a key (agent)
//	cfkey run --perm ... -- cmd args    run cmd with a key, revoke afterwards
//	cfkey list | revoke ID | perms | status
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"cfkey/internal/broker"
	"cfkey/internal/dashboard"
	"cfkey/internal/notify"
	"cfkey/internal/policy"
)

const usage = `cfkey - approve-on-request Cloudflare keys for agents

Human:
  cfkey serve [flags]       enter the master token and start a session
                            (stop with Ctrl+C: every key is revoked)
Agents:
  cfkey request [flags]     request a key; prints the token once approved
  cfkey run [flags] -- CMD  run CMD with CLOUDFLARE_API_TOKEN set, revoke after
  cfkey list                list live keys of this session
  cfkey revoke ID           revoke a key (request ID or token ID)
  cfkey perms [FILTER]      list permission names
  cfkey status              show whether a session is running

Run "cfkey <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "request":
		err = request(args)
	case "run":
		err = run(args)
	case "list":
		err = list()
	case "revoke":
		err = revoke(args)
	case "perms":
		err = perms(args)
	case "status":
		err = status()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		var exit exitCode
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "cfkey:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cfkey"), nil
}

func socketPath() (string, error) {
	if p := os.Getenv("CFKEY_SOCKET"); p != "" {
		return p, nil
	}
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cfkey.sock"), nil
}

// ---- serve (human side) ----

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 7787, "dashboard port on localhost")
	sessionTTL := fs.Duration("session-ttl", 12*time.Hour, "session lifetime; the session token expires then even if cfkey crashes")
	defaultTTL := fs.Duration("default-ttl", policy.DefaultRules.DefaultTTL, "key lifetime when the agent does not ask for one")
	maxTTL := fs.Duration("max-ttl", policy.DefaultRules.MaxTTL, "longest key lifetime an agent may request")
	approvalTimeout := fs.Duration("approval-timeout", 5*time.Minute, "how long a request waits for your decision")
	noSession := fs.Bool("no-session-token", false, "use the master token directly instead of a self-destructing session copy")
	_ = fs.Parse(args)

	dir, err := stateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sock, err := socketPath()
	if err != nil {
		return err
	}
	if c, err := net.Dial("unix", sock); err == nil {
		c.Close()
		return errors.New("a cfkey session is already running (" + sock + ")")
	}
	// Bind the dashboard port before asking for the token, so a busy port
	// fails fast.
	webLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return fmt.Errorf("dashboard port: %w", err)
	}

	master, err := readMasterToken()
	if err != nil {
		return err
	}

	cfg := broker.Config{
		Rules:           policy.Rules{DefaultTTL: *defaultTTL, MaxTTL: *maxTTL},
		SessionTTL:      *sessionTTL,
		ApprovalTimeout: *approvalTimeout,
		NoSessionToken:  *noSession,
		AuditLog:        filepath.Join(dir, "audit.log"),
		Notify: func(title, msg string) {
			fmt.Printf("\n%s  %s\n  %s\n  → approve or deny in the dashboard\n",
				time.Now().Format("15:04:05"), title, strings.ReplaceAll(msg, "\n", "\n  "))
			notify.Send(title, msg)
		},
	}
	fmt.Fprintln(os.Stderr, "Verifying master token and starting session...")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	b, rep, err := broker.Start(ctx, cfg, master)
	cancel()
	master = ""
	if err != nil {
		return err
	}
	for _, name := range rep.CleanedUp {
		fmt.Printf("Deleted leftover token from an earlier session: %s\n", name)
	}
	if rep.SessionTokenID != "" {
		fmt.Printf("Session token created; it deletes itself when you stop (expires %s at the latest).\n",
			rep.SessionExpires.Format("Mon 15:04"))
		fmt.Println("The master token has been dropped from memory.")
	} else {
		fmt.Println("Using the master token directly (--no-session-token).")
	}
	fmt.Printf("%d permissions available; accounts: %s\n", rep.PermissionCount, accountNames(rep))

	_ = os.Remove(sock) // stale socket from a crash; liveness was checked above
	sockLn, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		b.Shutdown(context.Background())
		return err
	}
	_ = os.Chmod(sock, 0o600)

	stop := make(chan string, 1)
	secret := randomHex(32)
	dash := dashboard.New(b, secret, fmt.Sprint(*port), func() {
		select {
		case stop <- "ended from the dashboard":
		default:
		}
	})
	go func() { _ = dash.Serve(webLn) }()
	go func() { _ = b.Serve(sockLn) }()

	fmt.Printf("\nDashboard (keep this link to yourself):\n  http://localhost:%d/#k=%s\n", *port, secret)
	fmt.Printf("Agents can now run `cfkey request`. Press Ctrl+C to end the session.\n")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	expiry := time.NewTimer(time.Until(b.Session().Expires))
	var why string
	select {
	case s := <-sigs:
		why = "received " + s.String()
	case why = <-stop:
	case <-expiry.C:
		why = "session expired"
	}
	signal.Reset(os.Interrupt, syscall.SIGTERM) // a second Ctrl+C kills immediately
	fmt.Printf("\nEnding session (%s): revoking keys...\n", why)
	sockLn.Close()
	webLn.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srep := b.Shutdown(ctx)
	_ = os.Remove(sock)
	fmt.Printf("Revoked %d key(s).\n", len(srep.Revoked))
	if rep.SessionTokenID != "" && srep.SessionTokenDeleted {
		fmt.Println("Session token deleted.")
	}
	for _, e := range srep.Errors {
		fmt.Println("ERROR:", e)
	}
	if len(srep.Errors) > 0 {
		fmt.Println("Some cleanup failed; leftovers expire on their own and are deleted on the next `cfkey serve`.")
		return exitCode(1)
	}
	return nil
}

func accountNames(rep broker.StartReport) string {
	var ns []string
	for _, a := range rep.Accounts {
		ns = append(ns, a.Name)
	}
	return strings.Join(ns, ", ")
}

// readMasterToken reads the token from the terminal without echo, or from
// stdin when it is piped (e.g. from a password manager CLI).
func readMasterToken() (string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return requireToken(line)
	}
	fmt.Fprint(os.Stderr, "Cloudflare master API token (input hidden): ")
	if err := stty("-echo"); err != nil {
		return "", fmt.Errorf("cannot disable terminal echo: %w", err)
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	_ = stty("echo")
	fmt.Fprintln(os.Stderr)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return requireToken(line)
}

func requireToken(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("no token entered")
	}
	return s, nil
}

func stty(arg string) error {
	c := exec.Command("stty", arg)
	c.Stdin = os.Stdin
	return c.Run()
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// ---- agent side ----

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func specFlags(fs *flag.FlagSet) func() policy.Spec {
	var perms, zones, ips multiFlag
	fs.Var(&perms, "perm", `permission name, e.g. "DNS Write" (repeatable; see cfkey perms)`)
	fs.Var(&zones, "zone", `zone name the zone-level permissions apply to (repeatable; "*" = all zones)`)
	fs.Var(&ips, "ip", "only allow the key from this IP or CIDR (repeatable)")
	account := fs.String("account", "", "account name or ID (needed only with several accounts)")
	ttl := fs.Duration("ttl", 0, "key lifetime, e.g. 30m or 2h (default: the session's default)")
	reason := fs.String("reason", "", "what the key is for; shown to the human (required)")
	return func() policy.Spec {
		return policy.Spec{Permissions: perms, Zones: zones, Account: *account, TTL: *ttl, IPs: ips, Reason: *reason}
	}
}

func dial() (*net.UnixConn, error) {
	sock, err := socketPath()
	if err != nil {
		return nil, err
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return nil, errors.New("no cfkey session is running; ask the human to start `cfkey serve`")
	}
	return c, nil
}

// call sends one message and returns the decoder for the replies.
func call(m broker.Message) (*net.UnixConn, *json.Decoder, error) {
	c, err := dial()
	if err != nil {
		return nil, nil, err
	}
	if err := json.NewEncoder(c).Encode(m); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, json.NewDecoder(c), nil
}

func callOnce(m broker.Message) (broker.Reply, error) {
	c, dec, err := call(m)
	if err != nil {
		return broker.Reply{}, err
	}
	defer c.Close()
	var r broker.Reply
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("reading reply: %w", err)
	}
	if r.Type == "error" {
		return r, errors.New(r.Error)
	}
	return r, nil
}

func obtain(spec policy.Spec) (*broker.Issued, error) {
	c, dec, err := call(broker.Message{Op: "request", Spec: &spec})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	for {
		var r broker.Reply
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("lost connection to cfkey: %w", err)
		}
		switch r.Type {
		case "pending":
			fmt.Fprintf(os.Stderr, "Request %s is waiting for human approval:\n", r.RequestID)
			for _, s := range r.Summary {
				fmt.Fprintf(os.Stderr, "  %s\n", s)
			}
		case "issued":
			return r.Issued, nil
		case "error":
			return nil, errors.New(r.Error)
		}
	}
}

func request(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	spec := specFlags(fs)
	asJSON := fs.Bool("json", false, "print token, IDs and expiry as JSON")
	_ = fs.Parse(args)
	issued, err := obtain(spec())
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(issued)
	}
	fmt.Fprintf(os.Stderr, "Approved. Key %s expires %s. Revoke when done: cfkey revoke %s\n",
		issued.TokenID, issued.ExpiresOn.Local().Format("15:04"), issued.RequestID)
	fmt.Println(issued.Token)
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	spec := specFlags(fs)
	envName := fs.String("env", "CLOUDFLARE_API_TOKEN", "environment variable that receives the token")
	_ = fs.Parse(args)
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return errors.New("usage: cfkey run [flags] -- command [args...]")
	}
	issued, err := obtain(spec())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Approved. Running %s; the key is revoked when it exits.\n", cmdArgs[0])

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), *envName+"="+issued.Token)
	// The child receives terminal signals itself; we stay alive to revoke.
	signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	runErr := cmd.Run()

	if _, err := callOnce(broker.Message{Op: "revoke", ID: issued.RequestID}); err != nil {
		fmt.Fprintf(os.Stderr, "cfkey: revoking key %s failed: %v (it still expires at %s)\n",
			issued.TokenID, err, issued.ExpiresOn.Local().Format("15:04"))
	} else {
		fmt.Fprintln(os.Stderr, "Key revoked.")
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitCode(exitErr.ExitCode())
	}
	return runErr
}

func list() error {
	r, err := callOnce(broker.Message{Op: "list"})
	if err != nil {
		return err
	}
	if len(r.Keys) == 0 {
		fmt.Println("No live keys.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "REQUEST\tTOKEN ID\tEXPIRES\tKEY\tREASON")
	for _, k := range r.Keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", k.ID, k.TokenID, k.ExpiresOn.Local().Format("15:04"),
			strings.Join(k.Grant.Summary, "; "), k.Grant.Reason)
	}
	return w.Flush()
}

func revoke(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: cfkey revoke ID")
	}
	if _, err := callOnce(broker.Message{Op: "revoke", ID: args[0]}); err != nil {
		return err
	}
	fmt.Println("Revoked.")
	return nil
}

func perms(args []string) error {
	r, err := callOnce(broker.Message{Op: "perms"})
	if err != nil {
		return err
	}
	filter := strings.ToLower(strings.Join(args, " "))
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PERMISSION\tSCOPE\tNOTE")
	for _, p := range r.Permissions {
		if filter != "" && !strings.Contains(strings.ToLower(p.Name), filter) {
			continue
		}
		note := ""
		if p.Forbidden != "" {
			note = "never granted"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Scope, note)
	}
	return w.Flush()
}

func status() error {
	r, err := callOnce(broker.Message{Op: "status"})
	if err != nil {
		return err
	}
	s := r.Session
	fmt.Printf("Session %s running since %s, ends %s. Max key TTL %s.\n",
		s.ID, s.Started.Local().Format("15:04"), s.Expires.Local().Format("Mon 15:04"), s.MaxTTL)
	return nil
}
