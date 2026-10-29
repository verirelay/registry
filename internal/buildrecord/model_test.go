package buildrecord

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestCanonicalBuildRecordAndVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	statement := BuildRecordStatement{
		Version:     BuildRecordVersion,
		Repository:  "https://github.com/verirelay/verirelay",
		GitCommit:   "2e8c3687b3fa1d3d03ffbb0e87bad7c6ca7b5a3e",
		GitTag:      "v1.0.0",
		Measurement: "sha384:" + strings.Repeat("ab", 48),
		CommittedAt: time.Date(2026, 8, 10, 12, 30, 0, 123456000, time.UTC),
	}

	payload, err := CanonicalBuildRecord(statement)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"verirelay-build-record/1","repository":"https://github.com/verirelay/verirelay","git_commit":"2e8c3687b3fa1d3d03ffbb0e87bad7c6ca7b5a3e","git_tag":"v1.0.0","measurement":"sha384:` + strings.Repeat("ab", 48) + `","committed_at":"2026-08-10T12:30:00.123456Z"}`
	if string(payload) != want {
		t.Fatalf("canonical bytes = %s", payload)
	}

	signature := ed25519.Sign(privateKey, payload)
	encoded := base64.RawURLEncoding.EncodeToString(signature)
	decoded, err := Verify(publicKey, payload, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != ed25519.SignatureSize {
		t.Fatalf("signature size = %d", len(decoded))
	}

	for _, nonCanonical := range []string{
		base64.URLEncoding.EncodeToString(signature),
		base64.StdEncoding.EncodeToString(signature),
		" " + encoded,
		encoded[:40] + "\n" + encoded[40:],
	} {
		if _, err := Verify(publicKey, payload, nonCanonical); err == nil {
			t.Fatalf("non-canonical signature %q passed verification", nonCanonical)
		}
	}

	payload[0] ^= 1
	if _, err := Verify(publicKey, payload, encoded); err == nil {
		t.Fatal("modified payload passed verification")
	}
}

func TestBuildRecordMustBeCanonical(t *testing.T) {
	base := BuildRecordStatement{
		Version:     BuildRecordVersion,
		Repository:  "https://github.com/verirelay/verirelay",
		GitCommit:   strings.Repeat("a", 40),
		GitTag:      "v1.0.0",
		Measurement: strings.Repeat("b", 96),
		CommittedAt: time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC),
	}
	if _, err := CanonicalBuildRecord(base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, field string
		mutate      func(*BuildRecordStatement)
	}{
		{"empty version", "version", func(s *BuildRecordStatement) { s.Version = "" }},
		{"padded version", "version", func(s *BuildRecordStatement) { s.Version += " " }},
		{"unknown version", "version", func(s *BuildRecordStatement) { s.Version = "verirelay-build-record/v1" }},
		{"relative repository", "repository", func(s *BuildRecordStatement) { s.Repository = "github.com/repo" }},
		{"padded repository", "repository", func(s *BuildRecordStatement) { s.Repository += " " }},
		{"short commit", "git_commit", func(s *BuildRecordStatement) { s.GitCommit = "abc123" }},
		{"uppercase commit", "git_commit", func(s *BuildRecordStatement) { s.GitCommit = strings.Repeat("A", 40) }},
		{"padded commit", "git_commit", func(s *BuildRecordStatement) { s.GitCommit = " " + s.GitCommit }},
		{"empty tag", "git_tag", func(s *BuildRecordStatement) { s.GitTag = "" }},
		{"padded tag", "git_tag", func(s *BuildRecordStatement) { s.GitTag += "\n" }},
		{"bad measurement", "measurement", func(s *BuildRecordStatement) { s.Measurement = "sha384:nope" }},
		{"uppercase measurement", "measurement", func(s *BuildRecordStatement) { s.Measurement = strings.Repeat("B", 96) }},
		{"uppercase algorithm", "measurement", func(s *BuildRecordStatement) { s.Measurement = "SHA384:" + s.Measurement }},
		{"padded measurement", "measurement", func(s *BuildRecordStatement) { s.Measurement = " " + s.Measurement }},
		{"zero time", "committed_at", func(s *BuildRecordStatement) { s.CommittedAt = time.Time{} }},
		{"non-UTC time", "committed_at", func(s *BuildRecordStatement) { s.CommittedAt = s.CommittedAt.In(time.FixedZone("JST", 9*60*60)) }},
		{"sub-microsecond time", "committed_at", func(s *BuildRecordStatement) { s.CommittedAt = s.CommittedAt.Add(time.Nanosecond) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if _, err := CanonicalBuildRecord(value); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error = %v, want one naming %s", err, test.field)
			}
		})
	}
}

func TestRevocationMustBeCanonical(t *testing.T) {
	base := RevocationStatement{
		Version:     RevocationVersion,
		Repository:  "https://github.com/verirelay/verirelay",
		GitCommit:   strings.Repeat("a", 40),
		GitTag:      "v1.0.0",
		Measurement: strings.Repeat("b", 96),
		Reason:      "known vulnerable dependency",
		RevokedAt:   time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC),
	}
	if _, err := CanonicalRevocation(base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, field string
		mutate      func(*RevocationStatement)
	}{
		{"empty version", "version", func(s *RevocationStatement) { s.Version = "" }},
		{"uppercase commit", "git_commit", func(s *RevocationStatement) { s.GitCommit = strings.Repeat("A", 40) }},
		{"empty reason", "reason", func(s *RevocationStatement) { s.Reason = "" }},
		{"padded reason", "reason", func(s *RevocationStatement) { s.Reason = " " + s.Reason }},
		{"long reason", "reason", func(s *RevocationStatement) { s.Reason = strings.Repeat("x", 1001) }},
		{"non-UTC time", "revoked_at", func(s *RevocationStatement) { s.RevokedAt = s.RevokedAt.Local() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if _, err := CanonicalRevocation(value); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error = %v, want one naming %s", err, test.field)
			}
		})
	}
}
