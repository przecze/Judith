//go:build !darwin && !linux

package peer

import (
	"errors"
	"net"
)

func peerPID(*net.UnixConn) (int, error) { return 0, errors.New("unsupported platform") }

func cwd(int) string { return "" }
