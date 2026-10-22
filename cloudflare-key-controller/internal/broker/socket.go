package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"cfkey/internal/peer"
	"cfkey/internal/policy"
)

// Message is a client request on the Unix socket: one JSON line.
type Message struct {
	Op   string       `json:"op"` // request | list | revoke | perms | status
	Spec *policy.Spec `json:"spec,omitempty"`
	ID   string       `json:"id,omitempty"`
}

// Reply is a server message: one JSON line. A "request" op gets a
// "pending" reply first and then a final "issued" or "error" reply.
type Reply struct {
	Type        string       `json:"type"` // pending | issued | ok | error
	Error       string       `json:"error,omitempty"`
	RequestID   string       `json:"request_id,omitempty"`
	Summary     []string     `json:"summary,omitempty"`
	Issued      *Issued      `json:"issued,omitempty"`
	Keys        []Request    `json:"keys,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
	Session     *SessionInfo `json:"session,omitempty"`
}

const maxMessage = 64 << 10

// Serve accepts agent connections on ln until it is closed.
func (b *Broker) Serve(ln *net.UnixListener) error {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go b.handle(conn)
	}
}

func (b *Broker) handle(conn *net.UnixConn) {
	defer conn.Close()
	enc := json.NewEncoder(conn)
	reply := func(r Reply) { _ = enc.Encode(r) }
	fail := func(err error) { reply(Reply{Type: "error", Error: err.Error()}) }

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxMessage), 4096).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		fail(errors.New("could not read request"))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		fail(errors.New("malformed request"))
		return
	}

	switch m.Op {
	case "request":
		if m.Spec == nil {
			fail(errors.New("missing spec"))
			return
		}
		// Cancel the request if the agent hangs up while waiting.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			cancel()
		}()
		r, err := b.Submit(ctx, *m.Spec, peer.Lookup(conn))
		if err != nil {
			fail(err)
			return
		}
		reply(Reply{Type: "pending", RequestID: r.ID, Summary: r.Grant.Summary})
		issued, err := b.Wait(ctx, r)
		if err != nil {
			fail(err)
			return
		}
		reply(Reply{Type: "issued", Issued: &issued})
	case "list":
		var keys []Request
		for _, r := range b.Snapshot() {
			if r.TokenID != "" && r.Status == StatusIssued {
				keys = append(keys, r)
			}
		}
		reply(Reply{Type: "ok", Keys: keys})
	case "revoke":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := b.Revoke(ctx, m.ID); err != nil {
			fail(err)
			return
		}
		reply(Reply{Type: "ok"})
	case "perms":
		reply(Reply{Type: "ok", Permissions: b.Permissions()})
	case "status":
		s := b.Session()
		reply(Reply{Type: "ok", Session: &s})
	default:
		fail(errors.New("unknown op"))
	}
}
