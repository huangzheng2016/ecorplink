package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"ecorplink/internal/config"
	"ecorplink/internal/corplink"
	"ecorplink/internal/daemon"
	"ecorplink/internal/daemonipc"
	"ecorplink/internal/forwarder"
	"ecorplink/internal/outbound"
	"ecorplink/internal/router"
	vpnpkg "ecorplink/internal/vpn"
	"ecorplink/internal/wgdevice"

	"gopkg.in/natefinch/lumberjack.v2"
)

var configPath = flag.String("c", "", "config file path")
var pidFilePathFlag = flag.String("pid-file", "", "pid file path")
var cleanupRoutesAndDNS = cleanupPersistedRoutes
var activeConnection connectionSupervisor

type loginCapabilities struct {
	VerifyTypes     []string
	LoginOrders     []string
	LoginEnableLDAP bool
}

type loginCapabilityCache struct {
	mu   sync.RWMutex
	caps loginCapabilities
}

func (c *loginCapabilityCache) Store(info *corplink.LoginMethodInfo) {
	if c == nil || info == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.caps = loginCapabilities{
		VerifyTypes:     append([]string(nil), info.VerifyTypes...),
		LoginOrders:     append([]string(nil), info.LoginOrders...),
		LoginEnableLDAP: info.LoginEnableLDAP,
	}
}

func (c *loginCapabilityCache) Load() loginCapabilities {
	if c == nil {
		return loginCapabilities{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return loginCapabilities{
		VerifyTypes:     append([]string(nil), c.caps.VerifyTypes...),
		LoginOrders:     append([]string(nil), c.caps.LoginOrders...),
		LoginEnableLDAP: c.caps.LoginEnableLDAP,
	}
}

func (c *loginCapabilityCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.caps = loginCapabilities{}
}

func shouldUseLDAPPassword(cfg *config.Config, caps loginCapabilities) bool {
	if cfg != nil && cfg.Corplink.Platform == "ldap" {
		return true
	}
	return caps.LoginEnableLDAP && slices.Contains(caps.VerifyTypes, "password") && firstLoginOrderIs(caps.LoginOrders, "ldap")
}

func firstLoginOrderIs(values []string, want string) bool {
	for _, v := range values {
		if v == "" {
			continue
		}
		return v == want
	}
	return false
}

func main() {
	if isWindowsService() {
		flag.Parse()
		if err := runService(); err != nil {
			log.Printf("[main] service fatal: %v", err)
			os.Exit(1)
		}
		return
	}

	// Already running as the daemon child — execute directly. This must happen
	// before subcommand dispatch because the parent may have been invoked as
	// "ecorplink-daemon -c config.json".
	if os.Getenv("ECORPLINK_DAEMON") == "1" {
		flag.Parse()
		if err := run(); err != nil {
			log.Printf("[main] fatal: %v", err)
			os.Exit(1)
		}
		return
	}

	// Subcommand dispatch (before flag.Parse)
	if cmd := daemonCommandFromArgs(os.Args); cmd != "" {
		switch cmd {
		case "stop":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStop()
			return
		case "restart":
			doStop()
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStart()
			return
		case "status":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStatus()
			return
		case "start":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStart()
			return
		case "install-service":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			if err := ensureAdmin(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := installService(*configPath, pidFilePath()); err != nil {
				fmt.Fprintf(os.Stderr, "install service: %v\n", err)
				os.Exit(1)
			}
			return
		case "uninstall-service":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			if err := ensureAdmin(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := uninstallService(); err != nil {
				fmt.Fprintf(os.Stderr, "uninstall service: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	flag.Parse()

	// Parent process: escalate if needed, then fork daemon child.
	doStart()
}

func daemonCommandFromArgs(args []string) string {
	if len(args) <= 1 || strings.HasPrefix(args[1], "-") {
		return ""
	}
	switch args[1] {
	case "start", "stop", "restart", "status", "install-service", "uninstall-service":
		return args[1]
	default:
		return ""
	}
}

// doStart escalates privileges if needed, then detaches the daemon child.
func doStart() {
	if err := ensureAdmin(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pidFile := pidFilePath()
	if pid, _ := daemon.ReadPidFile(pidFile); pid > 0 && daemon.IsRunning(pid) {
		fmt.Fprintf(os.Stderr, "daemon already running (pid %d)\n", pid)
		os.Exit(1)
	}
	daemon.RemovePidFile(pidFile) //nolint:errcheck

	pid, err := daemon.Detach(daemonArgs(os.Args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start daemon: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("daemon started (pid %d)\n", pid)
}

func daemonArgs(args []string) []string {
	if len(args) > 1 && (args[1] == "start" || args[1] == "restart") {
		out := make([]string, 0, len(args)-1)
		out = append(out, args[0])
		out = append(out, args[2:]...)
		return out
	}
	out := make([]string, len(args))
	copy(out, args)
	return out
}

func doStop() {
	pidFile := pidFilePath()
	pid, err := daemon.ReadPidFile(pidFile)
	if err != nil || !daemon.IsRunning(pid) {
		fmt.Println("daemon not running")
		daemon.RemovePidFile(pidFile)
		cleanupPersistedRoutes()
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("daemon not running")
		cleanupPersistedRoutes()
		return
	}
	if err := requestDaemonShutdown(); err == nil {
		if err := waitForProcessExit(pid, 10*time.Second, 100*time.Millisecond, daemon.IsRunning); err == nil {
			cleanupPersistedRoutes()
			daemon.RemovePidFile(pidFile)
			fmt.Printf("daemon stopped (pid %d)\n", pid)
			return
		}
	}
	if err := signalProcessStop(p); err != nil {
		fmt.Fprintf(os.Stderr, "failed to signal daemon %d: %v\n", pid, err)
		os.Exit(1)
	}
	if err := waitForProcessExit(pid, 10*time.Second, 100*time.Millisecond, daemon.IsRunning); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop daemon cleanly: %v\n", err)
		os.Exit(1)
	}
	cleanupPersistedRoutes()
	daemon.RemovePidFile(pidFile)
	fmt.Printf("daemon stopped (pid %d)\n", pid)
}

func requestDaemonShutdown() error {
	cl := daemonipc.NewClient(filepath.Join(ecorplinkDir(), "daemon.sock"))
	resp, err := cl.Send(daemonipc.Cmd{Action: daemonipc.ActionShutdown})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func waitForProcessExit(pid int, timeout, interval time.Duration, isRunning func(int) bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if !isRunning(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon %d did not exit within %s", pid, timeout)
		}
		time.Sleep(interval)
	}
}

func cleanupPersistedRoutes() {
	rm := router.NewRouteManager(router.NewPlatformRouter(""))
	rm.Cleanup()
	forwarder.CleanupPersistedHostRoutes()
	cleanupSystemDNS()
	flushDNSCache() // clear fake-IP entries left from previous tunnel session
}

func cleanupAfterReconnectDisconnect() {
	cleanupRoutesAndDNS()
}

func doStatus() {
	pidFile := pidFilePath()
	pid, err := daemon.ReadPidFile(pidFile)
	if err != nil || !daemon.IsRunning(pid) {
		fmt.Println("daemon not running")
		return
	}
	fmt.Printf("daemon running (pid %d)\n", pid)
}

func pidFilePath() string {
	if strings.TrimSpace(*pidFilePathFlag) != "" {
		return *pidFilePathFlag
	}
	return daemon.PidFilePath()
}

func run() error {
	return runWithContext(context.Background())
}

func runWithContext(ctx context.Context) error {
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		// First run: config file not yet created — write default and continue.
		if errors.Is(err, os.ErrNotExist) && *configPath != "" {
			cfg = config.DefaultConfig()
			if dir := filepath.Dir(*configPath); dir != "." {
				os.MkdirAll(dir, 0755) //nolint:errcheck
			}
			if data, merr := json.MarshalIndent(cfg, "", "  "); merr == nil {
				os.WriteFile(*configPath, append(data, '\n'), 0644) //nolint:errcheck
			}
		} else {
			return fmt.Errorf("load config: %w", err)
		}
	}
	setupLogging(cfg)
	log.Printf("[main] ecorplink daemon starting, pid: %d", os.Getpid())
	// Clean up any leftover routes/DNS from a previous crashed session.
	cleanupPersistedRoutes()

	pidFile := pidFilePath()
	if err := daemon.WritePidFile(pidFile, os.Getpid()); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer daemon.RemovePidFile(pidFile) //nolint:errcheck

	sessionPath := filepath.Join(ecorplinkDir(), "corplink_session.json")
	corplinkMgr := corplink.NewManagerWithConfig(sessionPath, cfg.Corplink)
	vpnMgr := vpnpkg.New(cfg)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sockPath := filepath.Join(ecorplinkDir(), "daemon.sock")
	sockSrv := daemonipc.NewServer(sockPath, buildHandler(cfg, corplinkMgr, vpnMgr, cancel))
	if err := sockSrv.Start(); err != nil {
		return fmt.Errorf("socket server: %w", err)
	}
	defer sockSrv.Stop()
	log.Printf("[main] daemon socket listening: %s", sockPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, shutdownSigs...)
	defer signal.Stop(sigCh)
	select {
	case sig := <-sigCh:
		log.Printf("[main] received %v, shutting down", sig)
	case <-ctx.Done():
		log.Printf("[main] context cancelled, shutting down")
	}
	activeConnection.Stop()
	vpnMgr.Disconnect() //nolint:errcheck
	return nil
}

func ecorplinkDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".ecorplink")
	}
	return filepath.Join(home, ".ecorplink")
}

func buildHandler(cfg *config.Config, cm *corplink.Manager, vm *vpnpkg.Manager, shutdown func()) daemonipc.Handler {
	loginCache := &loginCapabilityCache{}
	return func(cmd daemonipc.Cmd) daemonipc.Response {
		ctx := context.Background()
		cl := cm.Client()
		log.Printf("[ipc] action=%s", cmd.Action)
		resp := dispatchHandler(ctx, cmd, cl, cm, vm, cfg, shutdown, loginCache)
		if !resp.OK {
			log.Printf("[ipc] action=%s error=%s", cmd.Action, resp.Error)
		}
		return resp
	}
}

func dispatchHandler(ctx context.Context, cmd daemonipc.Cmd, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, cfg *config.Config, shutdown func(), loginCache *loginCapabilityCache) daemonipc.Response {
	switch cmd.Action {
	case daemonipc.ActionShutdown:
		activeConnection.Stop()
		if shutdown != nil {
			go shutdown()
		}
		return daemonipc.Response{OK: true}
	case daemonipc.ActionDiscover:
		if err := cl.DiscoverCompany(ctx, cmd.Company); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		loginCache.Clear()
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLoginMethods:
		info, err := cl.LoginMethods(ctx)
		if err != nil {
			loginCache.Clear()
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		loginCache.Store(info)
		return daemonipc.Response{OK: true, Data: info}

	case daemonipc.ActionSendCode:
		if err := cl.SendCode(ctx, cmd.CodeType, cmd.Account); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionVerifyCode:
		if err := cl.VerifyCode(ctx, cmd.CodeType, cmd.Account, cmd.Code); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLoginPassword:
		var err error
		if cfg.Corplink.Platform == "feilian_v1" {
			err = cl.LoginV1(ctx, cmd.Account, cmd.Password)
		} else if shouldUseLDAPPassword(cfg, loginCache.Load()) {
			err = cl.LoginWithLDAPPassword(ctx, cmd.Account, cmd.Password)
		} else {
			err = cl.LoginWithPassword(ctx, cmd.Account, cmd.Password)
		}
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionGetQRCode:
		qr, err := cl.GetQRCode(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: daemonipc.QRCodeDTO{
			LoginURL: qr.LoginURL, Token: qr.Token,
		}}

	case daemonipc.ActionPollQR:
		if err := cl.PollQRLogin(ctx, cmd.Token); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLogout:
		cl.Logout(ctx)
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionIsAuthenticated:
		return daemonipc.Response{OK: true, Data: cm.IsAuthenticated()}

	case daemonipc.ActionCleanupRoutes:
		cleanupPersistedRoutes() // includes cleanupSystemDNS + flushDNSCache
		log.Printf("[ipc] cleanup_routes: done")
		return daemonipc.Response{OK: true}

	case daemonipc.ActionListNodes:
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		dtos := make([]daemonipc.VPNNodeDTO, len(nodes))
		for i, n := range nodes {
			dtos[i] = daemonipc.VPNNodeDTO{
				ID: n.ID, Name: n.Name,
				ProtocolMode: n.ProtocolMode,
			}
		}
		return daemonipc.Response{OK: true, Data: dtos}

	case daemonipc.ActionPingNodes:
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		dtos := make([]daemonipc.VPNNodeDTO, len(nodes))
		var wg sync.WaitGroup
		for i, n := range nodes {
			wg.Add(1)
			go func(idx int, node corplink.VPNNode) {
				defer wg.Done()
				lat, _ := cl.PingNode(ctx, node)
				dtos[idx] = daemonipc.VPNNodeDTO{
					ID: node.ID, Name: node.Name,
					LatencyMs: lat, ProtocolMode: node.ProtocolMode,
				}
			}(i, n)
		}
		wg.Wait()
		return daemonipc.Response{OK: true, Data: dtos}

	case daemonipc.ActionPingSingle:
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: "list nodes: " + err.Error()}
		}
		for _, n := range nodes {
			if n.ID == cmd.NodeID {
				lat, _ := cl.PingNode(ctx, n)
				return daemonipc.Response{OK: true, Data: daemonipc.VPNNodeDTO{
					ID: n.ID, Name: n.Name,
					LatencyMs: lat, ProtocolMode: n.ProtocolMode,
				}}
			}
		}
		return daemonipc.Response{OK: false, Error: fmt.Sprintf("node %d not found", cmd.NodeID)}

	case daemonipc.ActionSetFollowSplitRoutes:
		vm.SetFollowSplitRoutes(cmd.FollowSplitRoutes)
		return daemonipc.Response{OK: true}

	case daemonipc.ActionReloadConfig:
		updated, err := config.LoadConfig(*configPath)
		if err != nil {
			return daemonipc.Response{OK: false, Error: "reload config: " + err.Error()}
		}
		*cfg = *updated
		setupLogging(cfg)
		cm.Configure(updated.Corplink)
		if err := vm.UpdateSOCKS5(updated.SOCKS5); err != nil {
			return daemonipc.Response{OK: false, Error: "reload socks5: " + err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionConnect:
		return handleConnect(ctx, cl, cm, vm, cfg, cmd.NodeID, cmd.FollowSplitRoutes)

	case daemonipc.ActionDisconnect:
		activeConnection.Stop()
		if err := vm.Disconnect(); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cleanupSystemDNS()
		flushDNSCache()
		return daemonipc.Response{OK: true}

	case daemonipc.ActionStatus:
		st := vm.GetStatus()
		return daemonipc.Response{OK: true, Data: daemonipc.VPNStatusDTO{
			Connected:    st.Connected,
			Reconnecting: st.Reconnecting,
			NodeName:     st.NodeName,
			VpnIP:        st.VpnIP,
			DNS:          st.DNS,
			Protocol:     st.Protocol,
			ConnectedAt:  st.ConnectedAt,
		}}

	case daemonipc.ActionGetStats:
		s := vm.GetStats()
		return daemonipc.Response{OK: true, Data: daemonipc.VPNStatsDTO{
			TxBytes: s.TxBytes,
			RxBytes: s.RxBytes,
		}}

	default:
		return daemonipc.Response{OK: false, Error: "unknown action: " + cmd.Action}
	}
}

func handleConnect(ctx context.Context, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, cfg *config.Config, nodeID int, followSplitRoutes bool) daemonipc.Response {
	resp, details := connectVPNOnce(ctx, cl, cm, vm, cfg, nodeID, followSplitRoutes)
	if !resp.OK {
		return resp
	}
	connCtx, connGen := activeConnection.Start(context.Background())
	startConnectionLoops(connCtx, connGen, cl, cm, vm, cfg, nodeID, followSplitRoutes, details.node, details.wgInfo.VpnIP.String(), details.pubB64)
	return resp
}

type connectDetails struct {
	node   corplink.VPNNode
	wgInfo *corplink.WGConnInfo
	pubB64 string
}

func connectVPNOnce(ctx context.Context, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, cfg *config.Config, nodeID int, followSplitRoutes bool) (daemonipc.Response, connectDetails) {
	nodes, err := cl.ListNodes(ctx)
	if err != nil {
		return daemonipc.Response{OK: false, Error: "list nodes: " + err.Error()}, connectDetails{}
	}
	var node corplink.VPNNode
	found := false
	for _, n := range nodes {
		if n.ID == nodeID {
			node = n
			found = true
			break
		}
	}
	if !found {
		return daemonipc.Response{OK: false, Error: fmt.Sprintf("node %d not found", nodeID)}, connectDetails{}
	}

	privB64, pubB64, err := corplink.GenerateKeyPair()
	if err != nil {
		return daemonipc.Response{OK: false, Error: "keygen: " + err.Error()}, connectDetails{}
	}

	wgInfo, err := cl.GetWGConfig(ctx, node, pubB64, cm.Session().TOTPSecret)
	if err != nil {
		return daemonipc.Response{OK: false, Error: "wg config: " + err.Error()}, connectDetails{}
	}

	// Determine physical interface
	physIface := cfg.DirectOutbound.Interface
	if physIface == "" {
		d := outbound.NewDirect("", nil)
		d.Init() //nolint:errcheck
		physIface = d.ResolvedIfaceName()
	}

	serverHost, _, _ := net.SplitHostPort(wgInfo.ServerEndpoint)

	// Parse fallback DNS from upstream config for use when VPN provides no DNS.
	var fallbackDNS netip.Addr
	for _, u := range cfg.DNS.Upstream {
		host, _, _ := net.SplitHostPort(u)
		if addr, err := netip.ParseAddr(host); err == nil {
			fallbackDNS = addr
			break
		}
	}

	// Add a direct host route for the Corplink API server so daemon HTTP
	// requests (keep-alive, node listing, etc.) never go through the TUN.
	if apiServer := cm.Session().Server; apiServer != "" && physIface != "" {
		if apiHost, err := resolveHostname(apiServer); err == nil {
			if rerr := forwarder.AddScopedHostRoute(apiHost, physIface); rerr != nil {
				log.Printf("[vpn] corplink api route %s: %v (continuing)", apiHost, rerr)
			}
		}
	}

	cc := vpnpkg.ConnectConfig{
		WG: wgdevice.Config{
			PrivateKeyB64:      privB64,
			ServerPublicKeyB64: wgInfo.ServerPublicKey,
			ServerEndpoint:     wgInfo.ServerEndpoint,
			ProtocolMode:       wgInfo.ProtocolMode,
			VpnIP:              wgInfo.VpnIP,
			DNSServers:         wgInfo.DNSServers,
			FallbackDNS:        fallbackDNS,
			MTU:                wgInfo.MTU,
		},
		SplitRoutes:       wgInfo.SplitRoutes,
		DomainSuffixes:    wgInfo.DomainSuffixes,
		PhysicalIface:     physIface,
		ServerIP:          serverHost,
		FollowSplitRoutes: followSplitRoutes,
	}

	if err := vm.Connect(node.Name, cc); err != nil {
		return daemonipc.Response{OK: false, Error: "connect: " + err.Error()}, connectDetails{}
	}
	flushDNSCache()
	// Point system DNS at the TUN's fakeip server so getaddrinfo()-based
	// resolvers (curl, browsers, etc.) also get fake IPs and go through TUN.
	tunIP := cfg.TUN.IP
	if tunIP == "" {
		tunIP = "172.30.77.1"
	}
	if tunName := cfg.TUN.Name; shouldSetupSystemDNS(cfg) && tunName != "" && tunIP != "" {
		if _, err2 := setupSystemDNS(tunName, tunIP); err2 != nil {
			log.Printf("[vpn] setup system DNS: %v (continuing)", err2)
		}
	} // clear any stale fake-IP entries before new tunnel is used
	proto := "UDP"
	if node.ProtocolMode == 1 {
		proto = "TCP"
	}
	dns := ""
	if len(wgInfo.DNSServers) > 0 {
		dns = wgInfo.DNSServers[0].String()
	}

	return daemonipc.Response{OK: true, Data: daemonipc.VPNStatusDTO{
		Connected:   true,
		NodeName:    node.Name,
		VpnIP:       wgInfo.VpnIP.String(),
		DNS:         dns,
		Protocol:    proto,
		ConnectedAt: time.Now().Unix(),
	}}, connectDetails{node: node, wgInfo: wgInfo, pubB64: pubB64}
}

func startConnectionLoops(ctx context.Context, gen uint64, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, cfg *config.Config, nodeID int, followSplitRoutes bool, node corplink.VPNNode, vpnIP, pubB64 string) {
	// Keep the VPN session alive (like corplink-rs keep_alive_vpn).
	// POST /vpn/report every 30 seconds to prevent server-side session expiry.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !activeConnection.IsCurrent(gen) || !vm.GetStatus().Connected {
				return
			}
			ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
			settings, err := cl.ReportVPN(ctx2, node, vpnIP, pubB64)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("[keepalive] report error: %v", err)
				}
			} else if settings != nil && activeConnection.IsCurrent(gen) {
				vm.UpdateSplitRoutes(settings.SplitRoutes, settings.DomainSuffixes)
			}
		}
	}()

	// Auto-reconnect: if the WireGuard tunnel goes dead, reconnect up to 10
	// times using fresh Corplink API credentials each time.
	go func() {
		const maxAttempts = 10
		attempts := 0
		reconnecting := false
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !activeConnection.IsCurrent(gen) {
				return
			}
			st := vm.GetStatus()
			if !st.Connected && !reconnecting {
				return // user manually disconnected
			}
			if st.Connected && !vm.IsConnectionDead() {
				attempts = 0
				reconnecting = false
				vm.SetReconnecting(false)
				continue
			}
			// Tunnel is dead (or previous reconnect attempt failed)
			if st.Connected {
				log.Printf("[reconnect] dead tunnel detected, tearing down TUN")
				vm.SetReconnecting(true)
				vm.Disconnect()
				cleanupAfterReconnectDisconnect()
			}
			if attempts >= maxAttempts {
				log.Printf("[reconnect] max %d attempts reached, giving up", maxAttempts)
				vm.SetReconnecting(false)
				cleanupSystemDNS()
				flushDNSCache()
				return
			}
			reconnecting = true
			attempts++
			log.Printf("[reconnect] tunnel dead, attempt %d/%d", attempts, maxAttempts)
			resp, details := connectVPNOnce(ctx, cl, cm, vm, cfg, nodeID, followSplitRoutes)
			if resp.OK {
				node = details.node
				vpnIP = details.wgInfo.VpnIP.String()
				pubB64 = details.pubB64
				log.Printf("[reconnect] succeeded (attempt %d)", attempts)
				attempts = 0
				reconnecting = false
				vm.SetReconnecting(false)
			} else if ctx.Err() == nil {
				log.Printf("[reconnect] attempt %d failed: %s", attempts, resp.Error)
			}
		}
	}()
}

// resolveHostname extracts the hostname from a URL and resolves it to an IP.
func resolveHostname(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("empty host in %q", rawURL)
	}
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("resolve %q: %w", host, err)
	}
	return addrs[0], nil
}

func firstNonSystem(upstream []string) string {
	for _, u := range upstream {
		if u != "" && u != "SYSTEM" {
			return u
		}
	}
	return ""
}

func setupLogging(cfg *config.Config) {
	logFile := expandPath(cfg.Log.File)
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return
	}
	// Pre-create log file owner-only; debug logs can include operational details.
	if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_RDONLY, 0600); err == nil {
		f.Close()
	}
	// If running as root via sudo, restore ownership to the original user.
	fixOwnership(logDir, logFile)

	log.SetOutput(&lumberjack.Logger{
		Filename:  logFile,
		MaxSize:   parseSizeMB(cfg.Log.MaxSize),
		MaxAge:    cfg.Log.MaxAge,
		Compress:  true,
		LocalTime: true,
	})
}

// fixOwnership chown log dir+file to SUDO_UID/SUDO_GID when running via sudo.
func fixOwnership(dir, file string) {
	if os.Getuid() != 0 {
		return
	}
	uid, uidOK := envInt("SUDO_UID")
	gid, gidOK := envInt("SUDO_GID")
	if !uidOK || !gidOK {
		return
	}
	os.Chown(dir, uid, gid)  //nolint:errcheck
	os.Chown(file, uid, gid) //nolint:errcheck
	os.Chmod(file, 0600)     //nolint:errcheck
}

func envInt(key string) (int, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func parseSizeMB(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	mul := 1
	if strings.HasSuffix(s, "GB") {
		mul, s = 1024, strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "MB") {
		s = strings.TrimSuffix(s, "MB")
	}
	s = strings.TrimSpace(s)
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n <= 0 {
		return 100
	}
	return n * mul
}
