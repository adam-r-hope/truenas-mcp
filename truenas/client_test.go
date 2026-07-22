package truenas

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

const testAPIKey = "1-verysecretapikey"

func TestRedactParamsAuthMethods(t *testing.T) {
	methods := []string{"auth.login_with_api_key", "auth.login", "auth.login_with_token"}
	for _, method := range methods {
		redacted := redactParams(method, []interface{}{"1-supersecretapikey"})
		out, _ := json.Marshal(redacted)
		if strings.Contains(string(out), "supersecretapikey") {
			t.Errorf("%s: API key leaked into log output: %s", method, out)
		}
		if redacted[0] != "[REDACTED]" {
			t.Errorf("%s: expected [REDACTED], got %v", method, redacted[0])
		}
	}
}

func TestRedactParamsSensitiveKeys(t *testing.T) {
	params := []interface{}{
		map[string]interface{}{
			"domainname": "example.com",
			"bindpw":     "hunter2",
			"configuration": map[string]interface{}{
				"password": "hunter3",
				"kerberos_realm": map[string]interface{}{
					"admin_password": "hunter4",
				},
			},
		},
	}
	redacted := redactParams("directoryservices.update", params)
	out, _ := json.Marshal(redacted)
	for _, secret := range []string{"hunter2", "hunter3", "hunter4"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("secret %q leaked into log output: %s", secret, out)
		}
	}
	if !strings.Contains(string(out), "example.com") {
		t.Errorf("non-sensitive value was redacted: %s", out)
	}
}

func TestRedactParamsLeavesOriginalUntouched(t *testing.T) {
	payload := map[string]interface{}{"bindpw": "hunter2"}
	redactParams("directoryservices.update", []interface{}{payload})
	if payload["bindpw"] != "hunter2" {
		t.Error("redactParams mutated the original params, which would corrupt the request sent on the wire")
	}
}

func TestRedactParamsNonSensitivePassthrough(t *testing.T) {
	params := []interface{}{"tank", map[string]interface{}{"name": "tank/data"}}
	redacted := redactParams("pool.dataset.create", params)
	out, _ := json.Marshal(redacted)
	orig, _ := json.Marshal(params)
	if string(out) != string(orig) {
		t.Errorf("non-sensitive params changed: got %s, want %s", out, orig)
	}
}

func TestRedactJSONForLog(t *testing.T) {
	in := []byte(`{"result":[{"method":"directoryservices.update","arguments":[{"bindpw":"hunter2","domain":"example.com"}],"password":"hunter3"}]}`)
	out := RedactJSONForLog(in)
	if strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "hunter3") {
		t.Errorf("secret survived redaction: %s", out)
	}
	if !strings.Contains(string(out), "example.com") {
		t.Errorf("non-sensitive value was redacted: %s", out)
	}

	// Non-JSON input must pass through unchanged rather than be dropped
	raw := []byte("not json")
	if string(RedactJSONForLog(raw)) != "not json" {
		t.Error("non-JSON input was altered")
	}
}

// startFakeTrueNAS runs a TLS WebSocket server speaking just enough of the
// TrueNAS protocol to drive connect, auth, and one follow-up call. If
// echoKeyInError is true, auth fails with an error message and trace that
// echo the submitted API key (simulating a server-side echo).
func startFakeTrueNAS(t *testing.T, echoKeyInError bool) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		var connectReq map[string]interface{}
		if err := conn.ReadJSON(&connectReq); err != nil {
			return
		}
		conn.WriteJSON(map[string]string{"msg": "connected", "session": "test"})

		for {
			var req APIRequest
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			switch {
			case req.Method == "auth.login_with_api_key" && echoKeyInError:
				conn.WriteJSON(map[string]interface{}{
					"id": req.ID, "msg": "failed",
					"error": map[string]interface{}{
						"code":    401,
						"message": "invalid API key: " + testAPIKey,
						"trace":   "Traceback: ValidationError('" + testAPIKey + "')",
					},
				})
			case req.Method == "auth.login_with_api_key":
				conn.WriteJSON(map[string]interface{}{"id": req.ID, "msg": "result", "result": true})
			default:
				// Any other call returns a result carrying a secret-bearing
				// field, like core.get_jobs job arguments do
				conn.WriteJSON(map[string]interface{}{
					"id": req.ID, "msg": "result",
					"result": map[string]interface{}{"bindpw": "responsesecret9", "domain": "example.com"},
				})
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runClientSession authenticates, makes one call, and returns everything the
// client logged plus the auth error (if any).
func runClientSession(t *testing.T, srv *httptest.Server) (string, error) {
	t.Helper()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	endpoint := "wss://" + strings.TrimPrefix(srv.URL, "https://") + "/websocket"
	client, err := NewClient(endpoint, testAPIKey, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	authErr := client.Authenticate()
	if authErr == nil {
		if _, err := client.Call("test.echo"); err != nil {
			t.Fatalf("Call: %v", err)
		}
	}
	return logBuf.String(), authErr
}

func TestLoggingDefaultModeOmitsBodies(t *testing.T) {
	SetDebugLogging(false)

	logs, authErr := runClientSession(t, startFakeTrueNAS(t, false))
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}

	if strings.Contains(logs, testAPIKey) {
		t.Errorf("API key leaked into log output:\n%s", logs)
	}
	if strings.Contains(logs, "responsesecret9") {
		t.Errorf("response secret leaked into log output:\n%s", logs)
	}
	if strings.Contains(logs, "params") {
		t.Errorf("request body logged outside debug mode:\n%s", logs)
	}
	if !strings.Contains(logs, "method=auth.login_with_api_key") {
		t.Errorf("expected request metadata line in log output:\n%s", logs)
	}
	if !strings.Contains(logs, "result=") {
		t.Errorf("expected response metadata line in log output:\n%s", logs)
	}
}

func TestLoggingDebugModeRedactsSecrets(t *testing.T) {
	SetDebugLogging(true)
	defer SetDebugLogging(false)

	logs, authErr := runClientSession(t, startFakeTrueNAS(t, false))
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}

	if strings.Contains(logs, testAPIKey) {
		t.Errorf("API key leaked into debug log output:\n%s", logs)
	}
	if strings.Contains(logs, "responsesecret9") {
		t.Errorf("response secret leaked into debug log output:\n%s", logs)
	}
	if !strings.Contains(logs, "[REDACTED]") {
		t.Errorf("expected redacted request body in debug log output:\n%s", logs)
	}
	if !strings.Contains(logs, "example.com") {
		t.Errorf("expected non-sensitive response content in debug log output:\n%s", logs)
	}
}

func TestServerEchoedKeyIsScrubbed(t *testing.T) {
	SetDebugLogging(true)
	defer SetDebugLogging(false)

	logs, authErr := runClientSession(t, startFakeTrueNAS(t, true))
	if authErr == nil {
		t.Fatal("expected authentication to fail")
	}

	if strings.Contains(logs, testAPIKey) {
		t.Errorf("server-echoed API key leaked into log output:\n%s", logs)
	}
	if strings.Contains(authErr.Error(), testAPIKey) {
		t.Errorf("server-echoed API key leaked into error message: %s", authErr)
	}
	if !strings.Contains(authErr.Error(), "[REDACTED]") {
		t.Errorf("expected scrubbed error message, got: %s", authErr)
	}
}
