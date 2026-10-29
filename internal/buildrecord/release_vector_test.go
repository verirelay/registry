package buildrecord

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testdata/registry-vector.json is a verbatim copy of the golden vector that
// Release signs in its own tests; Verifier keeps another copy.
func TestReleaseGoldenVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "registry-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		PublicKey string `json:"public_key"`
		Canonical string `json:"canonical"`
		Record    struct {
			Statement BuildRecordStatement `json:"statement"`
			Signature string               `json:"signature"`
		} `json:"record"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	payload, err := CanonicalBuildRecord(vector.Record.Statement)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != vector.Canonical {
		t.Fatalf("canonical bytes differ: %s", payload)
	}
	key, err := DecodePublicKey(vector.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(key, payload, vector.Record.Signature); err != nil {
		t.Fatal(err)
	}
}
