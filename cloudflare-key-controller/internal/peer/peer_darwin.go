package peer

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	solLocal     = 0     // SOL_LOCAL from <sys/un.h>
	localPeerPID = 0x002 // LOCAL_PEERPID from <sys/un.h>
)

func peerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var serr error
	err = raw.Control(func(fd uintptr) {
		pid, serr = syscall.GetsockoptInt(int(fd), solLocal, localPeerPID)
	})
	if err != nil {
		return 0, err
	}
	return pid, serr
}

func cwd(pid int) string {
	out, err := exec.Command("lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") {
			return line[1:]
		}
	}
	return ""
}
