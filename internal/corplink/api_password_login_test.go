package corplink

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLoginWithLDAPPasswordLooksUpAuthBeforeLogin(t *testing.T) {
	var got map[string]any
	var calls []string

	sess := LoadSession(t.TempDir() + "/session.json")
	sess.Server = "https://corplink.example"
	cl := NewClient(sess)
	cl.httpClient = &http.Client{Transport: ldapPasswordLoginTransport{t: t, got: &got, calls: &calls}}

	if err := cl.LoginWithLDAPPassword(context.Background(), " alice ", "secret"); err != nil {
		t.Fatal(err)
	}

	want := []string{"/api/lookup", "/api/login"}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	if got["user_name"] != "alice" {
		t.Fatalf("user_name = %v, want trimmed account", got["user_name"])
	}
	if got["password"] != "secret" {
		t.Fatalf("password = %v, want raw password", got["password"])
	}
	if got["platform"] != "ldap" {
		t.Fatalf("platform = %v, want ldap", got["platform"])
	}
}

type ldapPasswordLoginTransport struct {
	t     *testing.T
	got   *map[string]any
	calls *[]string
}

func (rt ldapPasswordLoginTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	*rt.calls = append(*rt.calls, r.URL.Path)
	switch r.URL.Path {
	case "/api/lookup":
		defer r.Body.Close()
		var lookup map[string]any
		if err := json.NewDecoder(r.Body).Decode(&lookup); err != nil {
			rt.t.Fatal(err)
		}
		if lookup["user_name"] != "alice" {
			rt.t.Fatalf("lookup user_name = %v, want alice", lookup["user_name"])
		}
		body := `{"code":0,"data":{"mfa":false,"auth":["mobile","password"]}}`
		return jsonResponse(r, body), nil
	case "/api/login":
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(rt.got); err != nil {
			rt.t.Fatal(err)
		}
		body := `{"code":0,"data":{"url":"otpauth://totp/ECorpLink:alice?secret=JBSWY3DPEHPK3PXP"}}`
		return jsonResponse(r, body), nil
	default:
		rt.t.Fatalf("path = %s, want /api/lookup or /api/login", r.URL.Path)
		return nil, nil
	}
}

func jsonResponse(r *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    r,
	}
}
