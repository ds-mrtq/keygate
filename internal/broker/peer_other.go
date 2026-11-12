//go:build !windows && !linux && !darwin

package broker

import "net"

func peerInfo(net.Conn) string { return "pid=unavailable" }
