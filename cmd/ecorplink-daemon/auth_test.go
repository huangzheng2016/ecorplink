package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ecorplink/internal/config"
	"ecorplink/internal/corplink"
	"ecorplink/internal/daemonipc"
)

func TestPasswordLoginPrefersLDAPWhenServerLoginOrderStartsWithLDAP(t *testing.T) {
	var loginBody map[string]any
	var calls []string
	var v1LoginCalled bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/api/login/setting":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 0,
				"data": map[string]any{
					"login_orders":      []string{"ldap", "feilian", "dingtalk"},
					"login_account":     []string{"userid", "email", "mobile"},
					"login_verify_type": []string{"password", "mobile"},
					"login_enable_ldap": true,
				},
			})
		case "/api/lookup":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 0,
				"data": map[string]any{"mfa": false, "auth": []string{"mobile", "password"}},
			})
		case "/api/login":
			if err := json.NewDecoder(r.Body).Decode(&loginBody); err != nil {
				t.Fatalf("decode login body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 0,
				"data": map[string]string{"url": "otpauth://totp/ECorpLink?secret=ABCDEF"},
			})
		case "/api/v1/login":
			v1LoginCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    10110001,
				"message": "用户名或密码错误",
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	cm := corplink.NewManagerWithConfig(filepath.Join(t.TempDir(), "session.json"), cfg.Corplink)
	cm.Session().Server = server.URL
	handler := buildHandler(cfg, cm, nil, nil)

	methods := handler(daemonipc.Cmd{Action: daemonipc.ActionLoginMethods})
	if !methods.OK {
		t.Fatalf("login_methods failed: %s", methods.Error)
	}

	resp := handler(daemonipc.Cmd{
		Action:   daemonipc.ActionLoginPassword,
		Account:  "0027009347",
		Password: "plain-secret",
	})

	if !resp.OK {
		t.Fatalf("login_password failed: %s; body=%v", resp.Error, loginBody)
	}
	if v1LoginCalled {
		t.Fatal("v1 login was called while LDAP is first in server login_orders")
	}
	if loginBody["platform"] != "ldap" {
		t.Fatalf("platform = %v, want ldap; body=%v", loginBody["platform"], loginBody)
	}
	if loginBody["password"] != "plain-secret" {
		t.Fatalf("password = %v, want raw password; body=%v", loginBody["password"], loginBody)
	}
	wantCalls := []string{"/api/login/setting", "/api/lookup", "/api/login"}
	if fmt.Sprint(calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
}
