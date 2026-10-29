package buildrecord

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	BuildRecordVersion = "verirelay-build-record/1"
	RevocationVersion  = "verirelay-revocation/1"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")

	commitPattern         = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	hexPattern            = regexp.MustCompile(`^[0-9a-f]+$`)
	measurementHexLengths = map[string]int{"sha256": 64, "sha384": 96, "sha512": 128}
)

// BuildRecordStatement is the stable, maintainer-signed build identity.
// Field order is part of the canonical JSON representation.
type BuildRecordStatement struct {
	Version     string    `json:"version"`
	Repository  string    `json:"repository"`
	GitCommit   string    `json:"git_commit"`
	GitTag      string    `json:"git_tag"`
	Measurement string    `json:"measurement"`
	CommittedAt time.Time `json:"committed_at"`
}

// RevocationStatement identifies one exact build identity as unsafe.
type RevocationStatement struct {
	Version     string    `json:"version"`
	Repository  string    `json:"repository"`
	GitCommit   string    `json:"git_commit"`
	GitTag      string    `json:"git_tag"`
	Measurement string    `json:"measurement"`
	Reason      string    `json:"reason"`
	RevokedAt   time.Time `json:"revoked_at"`
}

type Proof struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	SignedPayload string `json:"signed_payload"`
	Signature     string `json:"signature"`
}

type Revocation struct {
	ID        int64               `json:"id"`
	Statement RevocationStatement `json:"statement"`
	Proof     Proof               `json:"proof"`
	CreatedAt time.Time           `json:"created_at"`
}

type BuildRecord struct {
	ID         int64                `json:"id"`
	Statement  BuildRecordStatement `json:"statement"`
	Proof      Proof                `json:"proof"`
	Revoked    bool                 `json:"revoked"`
	Revocation *Revocation          `json:"revocation,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
}

type Store interface {
	Ping(context.Context) error
	CreateBuildRecord(context.Context, BuildRecordStatement, []byte, []byte) (BuildRecord, error)
	FindByTag(context.Context, string) ([]BuildRecord, error)
	FindByMeasurement(context.Context, string) ([]BuildRecord, error)
	CreateRevocation(context.Context, RevocationStatement, []byte, []byte) (Revocation, error)
}

// Validate checks that s is a canonical Build Record statement. Registry never
// rewrites a statement, so a non-canonical value is an error naming its field.
func (s BuildRecordStatement) Validate() error {
	if err := validateIdentity(s.Version, BuildRecordVersion, s.Repository, s.GitCommit, s.GitTag, s.Measurement); err != nil {
		return err
	}
	return validateTime("committed_at", s.CommittedAt)
}

// Validate checks that s is a canonical revocation statement.
func (s RevocationStatement) Validate() error {
	if err := validateIdentity(s.Version, RevocationVersion, s.Repository, s.GitCommit, s.GitTag, s.Measurement); err != nil {
		return err
	}
	if err := validateText("reason", s.Reason, 1000); err != nil {
		return err
	}
	return validateTime("revoked_at", s.RevokedAt)
}

func validateIdentity(version, expectedVersion, repository, gitCommit, gitTag, measurement string) error {
	if version != expectedVersion {
		return fmt.Errorf("version must be %q", expectedVersion)
	}
	if err := validateRepository(repository); err != nil {
		return err
	}
	if !commitPattern.MatchString(gitCommit) {
		return errors.New("git_commit must be a full 40 or 64 character lowercase hexadecimal commit hash")
	}
	if err := ValidateTag(gitTag); err != nil {
		return err
	}
	return ValidateMeasurement(measurement)
}

// CanonicalBuildRecord returns the canonical bytes of s, which must be canonical.
func CanonicalBuildRecord(s BuildRecordStatement) ([]byte, error) {
	return canonical(s)
}

// CanonicalRevocation returns the canonical bytes of s, which must be canonical.
func CanonicalRevocation(s RevocationStatement) ([]byte, error) {
	return canonical(s)
}

func canonical(s interface{ Validate() error }) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// Verify checks encodedSignature, which must be the canonical unpadded
// base64url of an Ed25519 signature, over payload.
func Verify(publicKey ed25519.PublicKey, payload []byte, encodedSignature string) ([]byte, error) {
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encodedSignature {
		return nil, errors.New("signature must be the canonical unpadded base64url of an Ed25519 signature")
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return nil, errors.New("invalid Ed25519 signature")
	}
	return signature, nil
}

// DecodePublicKey decodes the canonical unpadded base64url of an Ed25519
// public key.
func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != value {
		return nil, errors.New("public key must be the canonical unpadded base64url of an Ed25519 public key")
	}
	return key, nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func NewProof(publicKey ed25519.PublicKey, payload, signature []byte) Proof {
	return Proof{
		Algorithm:     "ed25519",
		KeyID:         KeyID(publicKey),
		SignedPayload: base64.RawURLEncoding.EncodeToString(payload),
		Signature:     base64.RawURLEncoding.EncodeToString(signature),
	}
}

// validateText checks that a string field has 1 to maxBytes bytes and no
// leading or trailing white space.
func validateText(field, value string, maxBytes int) error {
	if value == "" || len(value) > maxBytes {
		return fmt.Errorf("%s must contain 1 to %d bytes", field, maxBytes)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not have leading or trailing white space", field)
	}
	return nil
}

// validateTime checks that a timestamp field is set, in UTC, and has whole
// microseconds, the precision Registry stores.
func validateTime(field string, value time.Time) error {
	if value.IsZero() {
		return fmt.Errorf("%s is required", field)
	}
	if value.Location() != time.UTC || value.Nanosecond()%int(time.Microsecond) != 0 {
		return fmt.Errorf("%s must be in UTC with a Z suffix and at most microsecond precision", field)
	}
	return nil
}

// ValidateTag checks a git_tag: 1 to 255 bytes without leading or trailing
// white space.
func ValidateTag(value string) error {
	return validateText("git_tag", value, 255)
}

// ValidateMeasurement checks a measurement: a lowercase hex digest, bare or
// with its algorithm prefix.
func ValidateMeasurement(value string) error {
	digest := value
	if algorithm, prefixed, ok := strings.Cut(value, ":"); ok {
		expectedLength := measurementHexLengths[algorithm]
		if expectedLength == 0 {
			return errors.New("measurement algorithm must be sha256, sha384, or sha512")
		}
		digest = prefixed
		if len(digest) != expectedLength {
			return fmt.Errorf("%s measurement must contain %d lowercase hexadecimal characters", algorithm, expectedLength)
		}
	}
	if !hexPattern.MatchString(digest) || (len(digest) != 64 && len(digest) != 96 && len(digest) != 128) {
		return errors.New("measurement must be a 256, 384, or 512-bit lowercase hexadecimal digest")
	}
	return nil
}

func validateRepository(value string) error {
	if err := validateText("repository", value, 2048); err != nil {
		return err
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return errors.New("repository must be an absolute HTTP(S) URL")
	}
	return nil
}
