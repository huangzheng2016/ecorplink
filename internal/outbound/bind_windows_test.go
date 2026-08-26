//go:build windows

package outbound

import "testing"

func TestWindowsInterfaceIndexValueUsesNetworkByteOrder(t *testing.T) {
	if got, want := windowsInterfaceIndexValue(6), 0x06000000; got != want {
		t.Fatalf("windowsInterfaceIndexValue(6) = %#x, want %#x", got, want)
	}
}
