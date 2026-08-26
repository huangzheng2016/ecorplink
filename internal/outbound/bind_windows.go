//go:build windows

package outbound

import (
	"math/bits"
	"syscall"

	"golang.org/x/sys/windows"
)

const ipUnicastIf = 31 // IP_UNICAST_IF

// windowsInterfaceIndexValue converts an interface index to the network-byte
// order required by the Windows IP_UNICAST_IF socket option.
func windowsInterfaceIndexValue(ifIndex int) int {
	return int(bits.ReverseBytes32(uint32(ifIndex)))
}

func bindToInterface(ifIndex int, ifName string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		idx := windowsInterfaceIndexValue(ifIndex)
		err := c.Control(func(fd uintptr) {
			innerErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, idx)
		})
		if err != nil {
			return err
		}
		return innerErr
	}
}
