package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verirelay/registry/internal/buildrecord"
	"golang.org/x/crypto/bcrypt"
)

const testAPIKey = "test-api-key"

// memoryStore is an in-memory buildrecord.Store with the identity and
// revocation rules of the PostgreSQL store.
type memoryStore struct {
	records []buildrecord.BuildRecord
}

func (m *memoryStore) Ping(context.Context) error { return nil }

func (m *memoryStore) CreateBuildRecord(_ context.Context, statement buildrecord.BuildRecordStatement, _, _ []byte) (buildrecord.BuildRecord, error) {
	for _, record := range m.records {
		if sameIdentity(record.Statement, statement.Repository, statement.GitCommit, statement.GitTag, statement.Measurement) {
			return buildrecord.BuildRecord{}, buildrecord.ErrConflict
		}
	}
	record := buildrecord.BuildRecord{ID: int64(len(m.records) + 1), Statement: statement}
	m.records = append(m.records, record)
	return record, nil
}

func (m *memoryStore) FindByTag(_ context.Context, tag string) ([]buildrecord.BuildRecord, error) {
	return m.find(func(s buildrecord.BuildRecordStatement) bool { return s.GitTag == tag }), nil
}

func (m *memoryStore) FindByMeasurement(_ context.Context, measurement string) ([]buildrecord.BuildRecord, error) {
	return m.find(func(s buildrecord.BuildRecordStatement) bool { return s.Measurement == measurement }), nil
}

func (m *memoryStore) find(match func(buildrecord.BuildRecordStatement) bool) []buildrecord.BuildRecord {
	found := make([]buildrecord.BuildRecord, 0)
	for _, record := range m.records {
		if match(record.Statement) {
			found = append(found, record)
		}
	}
	return found
}

func (m *memoryStore) CreateRevocation(_ context.Context, statement buildrecord.RevocationStatement, _, _ []byte) (buildrecord.Revocation, error) {
	for i := range m.records {
		record := &m.records[i]
		if !sameIdentity(record.Statement, statement.Repository, statement.GitCommit, statement.GitTag, statement.Measurement) {
			continue
		}
		if record.Revoked {
			return buildrecord.Revocation{}, buildrecord.ErrConflict
		}
		revocation := buildrecord.Revocation{ID: record.ID, Statement: statement}
		record.Revoked, record.Revocation = true, &revocation
		return revocation, nil
	}
	return buildrecord.Revocation{}, buildrecord.ErrNotFound
}

func sameIdentity(s buildrecord.BuildRecordStatement, repository, commit, tag, measurement string) bool {
	return s.Repository == repository && s.GitCommit == commit && s.GitTag == tag && s.Measurement == measurement
}

func TestCreateBuildRecordRequiresBothCredentials(t *testing.T) {
	server, store, privateKey := newTestServer(t)
	body := signedBuildRecordBody(t, privateKey, validStatement())

	t.Run("missing API key", func(t *testing.T) {
		response := perform(t, server, http.MethodPost, "/v1/build-records", body, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("wrong API key", func(t *testing.T) {
		response := perform(t, server, http.MethodPost, "/v1/build-records", body, "wrong-api-key")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		var request signedBuildRecordRequest
		_ = json.Unmarshal(body, &request)
		request.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		invalidBody, _ := json.Marshal(request)
		response := perform(t, server, http.MethodPost, "/v1/build-records", invalidBody, testAPIKey)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("valid API key and signature", func(t *testing.T) {
		response := perform(t, server, http.MethodPost, "/v1/build-records", body, testAPIKey)
		if response.Code != http.StatusCreated {
			t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
		}
		if len(store.records) != 1 || store.records[0].Statement.Version != buildrecord.BuildRecordVersion {
			t.Fatalf("stored records = %#v", store.records)
		}
	})
}

func TestSignedWritesDecodeStrictly(t *testing.T) {
	server, store, privateKey := newTestServer(t)
	statement := validStatement()
	body := string(signedBuildRecordBody(t, privateKey, statement))
	payload, err := buildrecord.CanonicalBuildRecord(statement)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, payload)
	encoded := `"` + base64.RawURLEncoding.EncodeToString(signature) + `"`
	tag := `"git_tag":"v1.0.0"`
	revocation := string(signedRevocationBody(t, privateKey, revocationOf(statement)))

	tests := []struct {
		name, path, from, to string
		body                 string
		status               int
	}{
		{"duplicate key", "/v1/build-records", tag, tag + "," + tag, body, http.StatusBadRequest},
		{"duplicate key up to case", "/v1/build-records", tag, tag + `,"GIT_TAG":"v1.0.0"`, body, http.StatusBadRequest},
		{"key differing in case", "/v1/build-records", `"git_tag"`, `"Git_Tag"`, body, http.StatusBadRequest},
		{"top-level key differing in case", "/v1/build-records", `"signature"`, `"Signature"`, body, http.StatusBadRequest},
		{"unknown statement field", "/v1/build-records", tag, tag + `,"extra":1`, body, http.StatusBadRequest},
		{"unknown top-level field", "/v1/build-records", `{"statement"`, `{"extra":[1],"statement"`, body, http.StatusBadRequest},
		{"trailing value", "/v1/build-records", encoded + "}", encoded + "} {}", body, http.StatusBadRequest},
		{"padded signature", "/v1/build-records", encoded, `"` + base64.URLEncoding.EncodeToString(signature) + `"`, body, http.StatusForbidden},
		{"standard base64 signature", "/v1/build-records", encoded, `"` + base64.StdEncoding.EncodeToString(signature) + `"`, body, http.StatusForbidden},
		{"revocation key differing in case", "/v1/revocations", `"reason"`, `"Reason"`, revocation, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.body, test.from) {
				t.Fatalf("body %s does not contain %s", test.body, test.from)
			}
			mutated := strings.Replace(test.body, test.from, test.to, 1)
			response := perform(t, server, http.MethodPost, test.path, []byte(mutated), testAPIKey)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if len(store.records) != 0 {
		t.Fatalf("stored records = %#v", store.records)
	}
}

func TestNonCanonicalStatementsAreRejected(t *testing.T) {
	server, store, privateKey := newTestServer(t)
	statement := validStatement()
	body := string(signedBuildRecordBody(t, privateKey, statement))
	revocation := string(signedRevocationBody(t, privateKey, revocationOf(statement)))
	committedAt := `"committed_at":"2026-08-10T01:02:03Z"`

	tests := []struct {
		name, path, body, from, to, field string
	}{
		{"empty version", "/v1/build-records", body, `"version":"verirelay-build-record/1"`, `"version":""`, "version"},
		{"padded repository", "/v1/build-records", body, `"repository":"https://`, `"repository":" https://`, "repository"},
		{"uppercase commit", "/v1/build-records", body, statement.GitCommit, strings.ToUpper(statement.GitCommit), "git_commit"},
		{"padded tag", "/v1/build-records", body, `"git_tag":"v1.0.0"`, `"git_tag":"v1.0.0 "`, "git_tag"},
		{"uppercase measurement", "/v1/build-records", body, statement.Measurement, strings.ToUpper(statement.Measurement), "measurement"},
		{"offset time", "/v1/build-records", body, committedAt, `"committed_at":"2026-08-10T10:02:03+09:00"`, "committed_at"},
		{"zero offset time", "/v1/build-records", body, committedAt, `"committed_at":"2026-08-10T01:02:03+00:00"`, "committed_at"},
		{"nanosecond time", "/v1/build-records", body, committedAt, `"committed_at":"2026-08-10T01:02:03.000000001Z"`, "committed_at"},
		{"padded reason", "/v1/revocations", revocation, `"reason":"known`, `"reason":" known`, "reason"},
		{"offset revoked_at", "/v1/revocations", revocation, `"revoked_at":"2026-08-10T04:00:00Z"`, `"revoked_at":"2026-08-10T13:00:00+09:00"`, "revoked_at"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.body, test.from) {
				t.Fatalf("body %s does not contain %s", test.body, test.from)
			}
			mutated := strings.Replace(test.body, test.from, test.to, 1)
			response := perform(t, server, http.MethodPost, test.path, []byte(mutated), testAPIKey)
			var decoded errorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || decoded.Error.Code != "invalid_statement" || !strings.Contains(decoded.Error.Message, test.field) {
				t.Fatalf("status = %d, body = %s; want 400 invalid_statement naming %s", response.Code, response.Body.String(), test.field)
			}
		})
	}
	if len(store.records) != 0 {
		t.Fatalf("stored records = %#v", store.records)
	}
}

func TestLookupsRequireCanonicalValues(t *testing.T) {
	server, _, _ := newTestServer(t)
	measurement := validStatement().Measurement
	for target, code := range map[string]string{
		"/v1/build-records/by-tag/%20v1.0.0":                                      "invalid_tag",
		"/v1/build-records/by-measurement/" + strings.ToUpper(measurement):        "invalid_measurement",
		"/v1/build-records/by-measurement/SHA384:" + measurement:                  "invalid_measurement",
		"/v1/build-records/by-measurement/%20" + measurement:                      "invalid_measurement",
		"/v1/build-records/by-measurement/sha384:" + strings.ToUpper(measurement): "invalid_measurement",
	} {
		response := perform(t, server, http.MethodGet, target, nil, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), code) {
			t.Fatalf("GET %s: status = %d, body = %s; want 400 %s", target, response.Code, response.Body.String(), code)
		}
	}
}

func TestNewRejectsInvalidPasswordHash(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(nil)
	if _, err := New(&memoryStore{}, publicKey, "not-a-bcrypt-hash", nil); err == nil {
		t.Fatal("expected invalid bcrypt hash to be rejected")
	}
}

func TestPublicKey(t *testing.T) {
	server, _, privateKey := newTestServer(t)
	response := perform(t, server, http.MethodGet, "/v1/public-key", nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var info map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if info["public_key"] != base64.RawURLEncoding.EncodeToString(publicKey) || info["key_id"] != buildrecord.KeyID(publicKey) {
		t.Fatalf("public key info = %v", info)
	}
}

func TestQueryByTag(t *testing.T) {
	server, store, _ := newTestServer(t)
	for _, tag := range []string{"v1.2.3", "release/v1.2.3"} {
		statement := validStatement()
		statement.GitTag = tag
		store.records = append(store.records, buildrecord.BuildRecord{ID: int64(len(store.records) + 1), Statement: statement})
	}
	// Tags may contain "/": the rest of the path is the tag.
	for _, tag := range []string{"v1.2.3", "release/v1.2.3"} {
		result := lookup(t, server, "/v1/build-records/by-tag/"+tag)
		if result.Count != 1 || result.Items[0].Statement.GitTag != tag {
			t.Fatalf("by-tag %s = %#v", tag, result)
		}
	}
}

func TestSeveralBuildRecordsPerTag(t *testing.T) {
	server, _, privateKey := newTestServer(t)
	// Release registers one Build Record per Launch Measurement, all with the same tag and commit.
	var statements []buildrecord.BuildRecordStatement
	for i := range 5 {
		statement := validStatement()
		statement.Measurement = fmt.Sprintf("%096x", i+1)
		statements = append(statements, statement)
		response := perform(t, server, http.MethodPost, "/v1/build-records", signedBuildRecordBody(t, privateKey, statement), testAPIKey)
		if response.Code != http.StatusCreated {
			t.Fatalf("record %d: status = %d; body = %s", i, response.Code, response.Body.String())
		}
	}

	tagPath := "/v1/build-records/by-tag/" + validStatement().GitTag
	if result := lookup(t, server, tagPath); result.Count != len(statements) {
		t.Fatalf("by-tag count = %d, want %d", result.Count, len(statements))
	}
	for _, statement := range statements {
		result := lookup(t, server, "/v1/build-records/by-measurement/"+statement.Measurement)
		if result.Count != 1 || result.Items[0].Statement.Measurement != statement.Measurement {
			t.Fatalf("by-measurement %s = %#v", statement.Measurement, result)
		}
	}

	revoked := statements[0].Measurement
	response := perform(t, server, http.MethodPost, "/v1/revocations", signedRevocationBody(t, privateKey, revocationOf(statements[0])), testAPIKey)
	if response.Code != http.StatusCreated {
		t.Fatalf("revocation: status = %d; body = %s", response.Code, response.Body.String())
	}
	for _, item := range lookup(t, server, tagPath).Items {
		if item.Revoked != (item.Statement.Measurement == revoked) {
			t.Fatalf("measurement %s: revoked = %t", item.Statement.Measurement, item.Revoked)
		}
	}
}

func TestCreateRevocation(t *testing.T) {
	server, store, privateKey := newTestServer(t)
	statement := validStatement()
	if response := perform(t, server, http.MethodPost, "/v1/build-records", signedBuildRecordBody(t, privateKey, statement), testAPIKey); response.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	body := signedRevocationBody(t, privateKey, revocationOf(statement))

	response := perform(t, server, http.MethodPost, "/v1/revocations", body, testAPIKey)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	if revocation := store.records[0].Revocation; revocation == nil || revocation.Statement.Version != buildrecord.RevocationVersion {
		t.Fatalf("stored revocation = %#v", revocation)
	}

	response = perform(t, server, http.MethodPost, "/v1/revocations", body, testAPIKey)
	if response.Code != http.StatusConflict {
		t.Fatalf("second revocation: status = %d; body = %s", response.Code, response.Body.String())
	}

	other := statement
	other.GitTag = "v9.9.9"
	response = perform(t, server, http.MethodPost, "/v1/revocations", signedRevocationBody(t, privateKey, revocationOf(other)), testAPIKey)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown Build Record: status = %d; body = %s", response.Code, response.Body.String())
	}
}

func TestCreateBuildRecordConflict(t *testing.T) {
	server, _, privateKey := newTestServer(t)
	body := signedBuildRecordBody(t, privateKey, validStatement())
	for _, want := range []int{http.StatusCreated, http.StatusConflict} {
		if response := perform(t, server, http.MethodPost, "/v1/build-records", body, testAPIKey); response.Code != want {
			t.Fatalf("status = %d, want %d; body = %s", response.Code, want, response.Body.String())
		}
	}
}

func newTestServer(t *testing.T) (*Server, *memoryStore, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	server, err := New(store, publicKey, mustHash(t, testAPIKey), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server, store, privateKey
}

func validStatement() buildrecord.BuildRecordStatement {
	return buildrecord.BuildRecordStatement{
		Version:     buildrecord.BuildRecordVersion,
		Repository:  "https://github.com/verirelay/verirelay",
		GitCommit:   "2e8c3687b3fa1d3d03ffbb0e87bad7c6ca7b5a3e",
		GitTag:      "v1.0.0",
		Measurement: "29d42aa10f4e45975832b3f3f726ff3707cb5e97b4c2fdb7e7bf52fc2b80ef85d9c0d58f248f769bf74c38f0f6be5168",
		CommittedAt: time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC),
	}
}

func revocationOf(statement buildrecord.BuildRecordStatement) buildrecord.RevocationStatement {
	return buildrecord.RevocationStatement{
		Version:     buildrecord.RevocationVersion,
		Repository:  statement.Repository,
		GitCommit:   statement.GitCommit,
		GitTag:      statement.GitTag,
		Measurement: statement.Measurement,
		Reason:      "known vulnerable dependency",
		RevokedAt:   time.Date(2026, 8, 10, 4, 0, 0, 0, time.UTC),
	}
}

func signedBuildRecordBody(t *testing.T, privateKey ed25519.PrivateKey, statement buildrecord.BuildRecordStatement) []byte {
	t.Helper()
	payload, err := buildrecord.CanonicalBuildRecord(statement)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signedBuildRecordRequest{Statement: statement, Signature: sign(privateKey, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedRevocationBody(t *testing.T, privateKey ed25519.PrivateKey, statement buildrecord.RevocationStatement) []byte {
	t.Helper()
	payload, err := buildrecord.CanonicalRevocation(statement)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signedRevocationRequest{Statement: statement, Signature: sign(privateKey, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func sign(privateKey ed25519.PrivateKey, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

// lookup performs a successful lookup and checks the headers and count every
// lookup response carries.
func lookup(t *testing.T, handler http.Handler, target string) listResponse {
	t.Helper()
	response := perform(t, handler, http.MethodGet, target, nil, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d; body = %s", target, response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("GET %s: Cache-Control = %q", target, got)
	}
	var result listResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Count != len(result.Items) {
		t.Fatalf("GET %s: count = %d with %d items", target, result.Count, len(result.Items))
	}
	return result
}

func perform(t *testing.T, handler http.Handler, method, target string, body []byte, apiKey string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(body))
	if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}
