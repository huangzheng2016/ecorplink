package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ecorplink/internal/config"
	"ecorplink/internal/corplink"
	"ecorplink/internal/routetable"
	vpnpkg "ecorplink/internal/vpn"
)

type cleanupTestResolver map[string][]string

func (r cleanupTestResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r[host], nil
}

func TestWaitForProcessExitReturnsAfterProcessStops(t *testing.T) {
	checks := 0
	err := waitForProcessExit(1234, 100*time.Millisecond, time.Millisecond, func(pid int) bool {
		if pid != 1234 {
			t.Fatalf("pid = %d, want 1234", pid)
		}
		checks++
		return checks < 3
	})
	if err != nil {
		t.Fatalf("waitForProcessExit returned error: %v", err)
	}
	if checks != 3 {
		t.Fatalf("checks = %d, want 3", checks)
	}
}

func TestWaitForProcessExitTimesOut(t *testing.T) {
	err := waitForProcessExit(1234, 3*time.Millisecond, time.Millisecond, func(pid int) bool {
		return true
	})
	if err == nil {
		t.Fatal("waitForProcessExit should time out while process is still running")
	}
}

func TestDaemonArgsStripStartSubcommand(t *testing.T) {
	got := daemonArgs([]string{"ecorplink", "start", "-c", "config.json", "--pid-file", "/tmp/ecorplink.pid"})
	want := []string{"ecorplink", "-c", "config.json", "--pid-file", "/tmp/ecorplink.pid"}
	if len(got) != len(want) {
		t.Fatalf("daemonArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("daemonArgs = %v, want %v", got, want)
		}
	}
}

func TestDaemonArgsKeepFlagOnlyInvocation(t *testing.T) {
	got := daemonArgs([]string{"ecorplink", "-c", "config.json"})
	want := []string{"ecorplink", "-c", "config.json"}
	if len(got) != len(want) {
		t.Fatalf("daemonArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("daemonArgs = %v, want %v", got, want)
		}
	}
}

func TestDaemonCommandFromArgs(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"ecorplink-daemon", "install-service", "-c", "config.json"}, "install-service"},
		{[]string{"ecorplink-daemon", "uninstall-service"}, "uninstall-service"},
		{[]string{"ecorplink-daemon", "stop"}, "stop"},
		{[]string{"ecorplink-daemon", "-c", "config.json"}, ""},
	}
	for _, tt := range tests {
		if got := daemonCommandFromArgs(tt.args); got != tt.want {
			t.Fatalf("daemonCommandFromArgs(%v) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestLinuxSystemdServiceUnit(t *testing.T) {
	unit := linuxSystemdServiceUnit("/opt/ECorpLink/ecorplink-daemon", "/home/alice/.ecorplink/config.json", "/home/alice/.ecorplink/ecorplink.pid", "/home/alice/.ecorplink")
	for _, want := range []string{
		"Description=ECorpLink daemon",
		`Environment="ECORPLINK_DAEMON=1"`,
		`Environment="HOME=/home/alice"`,
		`WorkingDirectory="/home/alice/.ecorplink"`,
		`ExecStart="/opt/ECorpLink/ecorplink-daemon" -c "/home/alice/.ecorplink/config.json" --pid-file "/home/alice/.ecorplink/ecorplink.pid"`,
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("linux systemd unit missing %q:\n%s", want, unit)
		}
	}
}

func TestCleanupAfterReconnectDisconnectRunsFullNetworkCleanup(t *testing.T) {
	called := false
	orig := cleanupRoutesAndDNS
	cleanupRoutesAndDNS = func() {
		called = true
	}
	defer func() {
		cleanupRoutesAndDNS = orig
	}()

	cleanupAfterReconnectDisconnect()

	if !called {
		t.Fatal("reconnect teardown should run full route and DNS cleanup")
	}
}

func TestKnownCleanupHostIPsIncludesDNSAndAPIServer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DNS.Upstream = []string{"223.6.6.6:53", "SYSTEM", "bad-value"}
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "session.json")
	mgr := corplink.NewManagerWithConfig(sessionPath, cfg.Corplink)
	mgr.Session().Server = "https://vpn.example.invalid:443"

	got := knownCleanupHostIPs(context.Background(), cfg, mgr, cleanupTestResolver{
		"vpn.example.invalid": []string{"203.0.113.10", "not-an-ip", "203.0.113.10"},
	})
	want := []string{"223.6.6.6", "203.0.113.10"}
	if len(got) != len(want) {
		t.Fatalf("cleanup ips = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("cleanup ips = %v, want %v", got, want)
		}
	}
}

func TestRefinedCaptureCIDRsSplitsOtherTunnelRoutes(t *testing.T) {
	entries := []routetable.Entry{
		{Dest: mustTestCIDR("64.0.0.0/2"), Iface: "utun6"},
		{Dest: mustTestCIDR("192.168.1.0/24"), Iface: "en0"},
		{Dest: mustTestCIDR("198.18.0.0/15"), Iface: "utun100"},
		{Dest: mustTestCIDR("127.0.0.0/8"), Iface: "utun6"},
	}
	got := vpnpkg.RefinedCaptureCIDRs(entries, "utun100")
	want := []string{"64.0.0.0/3", "96.0.0.0/3"}
	if len(got) != len(want) {
		t.Fatalf("refinedCaptureCIDRs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("refinedCaptureCIDRs = %v, want %v", got, want)
		}
	}
}

func mustTestCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestShouldSetupSystemDNSHonorsConfig(t *testing.T) {
	if shouldSetupSystemDNS(nil) {
		t.Fatal("nil config should not set system DNS")
	}
	cfg := config.DefaultConfig()
	cfg.DNS.SystemHijack = false
	if shouldSetupSystemDNS(cfg) {
		t.Fatal("system_hijack=false should not set system DNS")
	}
	cfg.DNS.SystemHijack = true
	if !shouldSetupSystemDNS(cfg) {
		t.Fatal("system_hijack=true should set system DNS")
	}
}

func TestLoadOrCreateConfigRepairsOwnershipForDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var repaired []string
	orig := repairOwnership
	repairOwnership = func(path string) error {
		repaired = append(repaired, path)
		return nil
	}
	defer func() {
		repairOwnership = orig
	}()

	cfg, err := loadOrCreateConfig(path)
	if err != nil {
		t.Fatalf("loadOrCreateConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("loadOrCreateConfig returned nil config")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
	want := []string{filepath.Dir(path), path}
	if len(repaired) != len(want) {
		t.Fatalf("repair calls = %v, want %v", repaired, want)
	}
	for i := range want {
		if repaired[i] != want[i] {
			t.Fatalf("repair calls = %v, want %v", repaired, want)
		}
	}
}

func TestLoadOrCreateConfigRepairsOwnershipForExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"enabled":true,"type":"GEOIP","value":"CN","policy":"DIRECT"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	var repaired []string
	orig := repairOwnership
	repairOwnership = func(path string) error {
		repaired = append(repaired, path)
		return nil
	}
	defer func() {
		repairOwnership = orig
	}()

	cfg, err := loadOrCreateConfig(path)
	if err != nil {
		t.Fatalf("loadOrCreateConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("loadOrCreateConfig returned nil config")
	}
	want := []string{dir, path}
	if len(repaired) != len(want) {
		t.Fatalf("repair calls = %v, want %v", repaired, want)
	}
	for i := range want {
		if repaired[i] != want[i] {
			t.Fatalf("repair calls = %v, want %v", repaired, want)
		}
	}
}

func TestSetupLoggingRepairsLogDirAndFileOwnership(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "logs", "ecorplink.log")
	var repaired []string
	orig := repairOwnership
	repairOwnership = func(path string) error {
		repaired = append(repaired, path)
		return nil
	}
	defer func() {
		repairOwnership = orig
	}()

	cfg := config.DefaultConfig()
	cfg.Log.File = logFile
	setupLogging(cfg)

	want := []string{filepath.Dir(logFile), logFile}
	if len(repaired) != len(want) {
		t.Fatalf("repair calls = %v, want %v", repaired, want)
	}
	for i := range want {
		if repaired[i] != want[i] {
			t.Fatalf("repair calls = %v, want %v", repaired, want)
		}
	}
}

func TestConnectionSupervisorCancelsPreviousSession(t *testing.T) {
	var sup connectionSupervisor
	ctx1, gen1 := sup.Start(context.Background())
	ctx2, gen2 := sup.Start(context.Background())
	if gen2 <= gen1 {
		t.Fatalf("generation did not advance: %d -> %d", gen1, gen2)
	}
	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("previous connection context was not cancelled")
	}
	select {
	case <-ctx2.Done():
		t.Fatal("current connection context should still be active")
	default:
	}
	if sup.IsCurrent(gen1) {
		t.Fatal("old generation should not be current")
	}
	if !sup.IsCurrent(gen2) {
		t.Fatal("new generation should be current")
	}
	sup.Stop()
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("current connection context was not cancelled by Stop")
	}
}

func TestResolveHostnameWithResolverUsesProvidedResolver(t *testing.T) {
	resolver := &fakeHostResolver{
		addrs: map[string][]string{"control.example.test": {"203.0.113.77"}},
	}

	got, err := resolveHostnameWithResolver(context.Background(), "https://control.example.test/api", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.77" {
		t.Fatalf("resolved host = %q, want 203.0.113.77", got)
	}
	if resolver.queries[0] != "control.example.test" {
		t.Fatalf("resolver queries = %v, want control.example.test", resolver.queries)
	}
}

func TestEnsureCorplinkNodeRouteAddsRouteForLiteralNodeIP(t *testing.T) {
	var calls []string
	orig := addScopedHostRoute
	addScopedHostRoute = func(ip, iface string) error {
		calls = append(calls, ip+" "+iface)
		return nil
	}
	defer func() {
		addScopedHostRoute = orig
	}()

	ensureCorplinkNodeRoute(corplink.VPNNode{IP: "198.51.100.10"}, "en0")

	if len(calls) != 1 || calls[0] != "198.51.100.10 en0" {
		t.Fatalf("route calls = %v, want [198.51.100.10 en0]", calls)
	}
}

type fakeHostResolver struct {
	addrs   map[string][]string
	queries []string
}

func (r *fakeHostResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.queries = append(r.queries, host)
	if addrs := r.addrs[host]; len(addrs) > 0 {
		return addrs, nil
	}
	return nil, os.ErrNotExist
}
