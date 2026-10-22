// Package peer identifies the local process on the other end of a Unix
// socket connection, so the approval prompt can say who is asking.
//
// The process ID comes from the kernel and cannot be forged, but process
// names, arguments and working directories are chosen by the process itself,
// so they are hints for the human, not proof of identity.
package peer

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Info describes the requesting process.
type Info struct {
	PID   int      `json:"pid"`
	Chain []string `json:"chain"` // the process and its ancestors, nearest first
	Cwd   string   `json:"cwd,omitempty"`
}

// Lookup describes the process connected on conn.
func Lookup(conn *net.UnixConn) Info {
	pid, err := peerPID(conn)
	if err != nil || pid <= 0 {
		return Info{}
	}
	info := Info{PID: pid, Cwd: cwd(pid)}
	p := pid
	for i := 0; i < 5 && p > 1; i++ {
		ppid, comm, ok := psEntry(p)
		if !ok {
			break
		}
		info.Chain = append(info.Chain, comm+" ("+strconv.Itoa(p)+")")
		p = ppid
	}
	return info
}

func psEntry(pid int) (ppid int, comm string, ok bool) {
	out, err := exec.Command("ps", "-o", "ppid=,comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, "", false
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return 0, "", false
	}
	ppid, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", false
	}
	comm = strings.Join(fields[1:], " ")
	if i := strings.LastIndex(comm, "/"); i >= 0 {
		comm = comm[i+1:]
	}
	return ppid, comm, true
}
