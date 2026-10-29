package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/verirelay/registry/internal/buildrecord"
)

// testDatabaseEnv names a PostgreSQL URL for integration tests. Tests that
// need a database are skipped when it is unset.
const testDatabaseEnv = "REGISTRY_TEST_DATABASE_URL"

var _ buildrecord.Store = (*Postgres)(nil)

func TestMain(m *testing.M) {
	// A local zone other than UTC makes assertUTC fail if a scan returns local time.
	time.Local = time.FixedZone("UTC+9", 9*60*60)
	os.Exit(m.Run())
}

type testStore struct {
	*Postgres
	privateKey ed25519.PrivateKey
	schema     string
}

// newTestStore opens a store whose search_path points at a fresh schema, so
// tests can run in parallel without seeing each other's rows. The schema is
// dropped when the test finishes.
func newTestStore(t *testing.T) *testStore {
	t.Helper()
	databaseURL := os.Getenv(testDatabaseEnv)
	if databaseURL == "" {
		t.Skipf("%s is not set", testDatabaseEnv)
	}
	ctx := context.Background()

	schema := "store_test_" + randomHex(t, 8)
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		defer func() { _ = admin.Close(ctx) }()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, withConnParam(t, databaseURL, "search_path", schema), 4, publicKey)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(store.Close)
	return &testStore{Postgres: store, privateKey: privateKey, schema: schema}
}

func newStoreWithSchema(t *testing.T) *testStore {
	t.Helper()
	store := newTestStore(t)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	return store
}

// withConnParam adds a connection parameter to either a URL or a
// keyword/value connection string.
func withConnParam(t *testing.T, databaseURL, key, value string) string {
	t.Helper()
	if !strings.Contains(databaseURL, "://") {
		return databaseURL + " " + key + "=" + value
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse %s: %v", testDatabaseEnv, err)
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}

func testCommit(n int) string {
	return fmt.Sprintf("%040x", n)
}

func testMeasurement(n int) string {
	return fmt.Sprintf("sha384:%096x", n)
}

var baseTime = time.Date(2026, 8, 10, 12, 30, 0, 0, time.UTC)

func testStatement(commit, tag, measurement int, committedAt time.Time) buildrecord.BuildRecordStatement {
	return buildrecord.BuildRecordStatement{
		Version:     buildrecord.BuildRecordVersion,
		Repository:  "https://github.com/verirelay/verirelay",
		GitCommit:   testCommit(commit),
		GitTag:      fmt.Sprintf("v1.0.%d", tag),
		Measurement: testMeasurement(measurement),
		CommittedAt: committedAt,
	}
}

func revocationFor(statement buildrecord.BuildRecordStatement, reason string, revokedAt time.Time) buildrecord.RevocationStatement {
	return buildrecord.RevocationStatement{
		Version:     buildrecord.RevocationVersion,
		Repository:  statement.Repository,
		GitCommit:   statement.GitCommit,
		GitTag:      statement.GitTag,
		Measurement: statement.Measurement,
		Reason:      reason,
		RevokedAt:   revokedAt,
	}
}

func (s *testStore) createBuildRecord(t *testing.T, statement buildrecord.BuildRecordStatement) (buildrecord.BuildRecord, []byte, []byte) {
	t.Helper()
	payload, err := buildrecord.CanonicalBuildRecord(statement)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(s.privateKey, payload)
	created, err := s.CreateBuildRecord(context.Background(), statement, payload, signature)
	if err != nil {
		t.Fatalf("create build record: %v", err)
	}
	return created, payload, signature
}

func (s *testStore) createRevocation(t *testing.T, statement buildrecord.RevocationStatement) (buildrecord.Revocation, []byte, []byte) {
	t.Helper()
	payload, err := buildrecord.CanonicalRevocation(statement)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(s.privateKey, payload)
	created, err := s.CreateRevocation(context.Background(), statement, payload, signature)
	if err != nil {
		t.Fatalf("create revocation: %v", err)
	}
	return created, payload, signature
}

func (s *testStore) proof(payload, signature []byte) buildrecord.Proof {
	return buildrecord.NewProof(s.publicKey, payload, signature)
}

func buildRecordIDs(items []buildrecord.BuildRecord) []int64 {
	ids := make([]int64, len(items))
	for i, item := range items {
		ids[i] = item.ID
	}
	return ids
}

func assertUTC(t *testing.T, name string, value time.Time) {
	t.Helper()
	if value.Location() != time.UTC {
		t.Fatalf("%s = %s, want UTC", name, value)
	}
}

func assertIDs(t *testing.T, name string, got, want []int64) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s ids = %v, want %v", name, got, want)
	}
}

func assertPgErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want PostgreSQL error %s", err, code)
	}
}

func assertStatementEqual(t *testing.T, got, want buildrecord.BuildRecordStatement) {
	t.Helper()
	if got.Version != want.Version || got.Repository != want.Repository || got.GitCommit != want.GitCommit ||
		got.GitTag != want.GitTag || got.Measurement != want.Measurement || !got.CommittedAt.Equal(want.CommittedAt) {
		t.Fatalf("statement = %+v, want %+v", got, want)
	}
}

func assertRevocationStatementEqual(t *testing.T, got, want buildrecord.RevocationStatement) {
	t.Helper()
	if got.Version != want.Version || got.Repository != want.Repository || got.GitCommit != want.GitCommit ||
		got.GitTag != want.GitTag || got.Measurement != want.Measurement || got.Reason != want.Reason ||
		!got.RevokedAt.Equal(want.RevokedAt) {
		t.Fatalf("revocation statement = %+v, want %+v", got, want)
	}
}

func TestOpenRejectsInvalidURL(t *testing.T) {
	_, err := Open(context.Background(), "postgres://%zz", 4, nil)
	if err == nil || !strings.Contains(err.Error(), "parse PostgreSQL configuration") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenReportsUnreachableDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Open(ctx, "postgres://user:pwd@127.0.0.1:1/db?sslmode=disable&connect_timeout=2", 4, nil)
	if err == nil || !strings.Contains(err.Error(), "connect to database") {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenConfiguresPool(t *testing.T) {
	databaseURL := os.Getenv(testDatabaseEnv)
	if databaseURL == "" {
		t.Skipf("%s is not set", testDatabaseEnv)
	}
	ctx := context.Background()
	tests := []struct {
		name     string
		url      string
		maxConns int32
		minConns int32
	}{
		{name: "default min conns", url: databaseURL, maxConns: 8, minConns: 2},
		{name: "small pool", url: databaseURL, maxConns: 3, minConns: 0},
		{name: "explicit min conns", url: withConnParam(t, databaseURL, "pool_min_conns", "1"), maxConns: 8, minConns: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := Open(ctx, tt.url, tt.maxConns, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			config := store.pool.Config()
			if config.MaxConns != tt.maxConns || config.MinConns != tt.minConns {
				t.Fatalf("max/min conns = %d/%d, want %d/%d", config.MaxConns, config.MinConns, tt.maxConns, tt.minConns)
			}
			if config.MaxConnLifetime != time.Hour || config.MaxConnIdleTime != 15*time.Minute || config.HealthCheckPeriod != 30*time.Second {
				t.Fatalf("unexpected pool timings: %v %v %v", config.MaxConnLifetime, config.MaxConnIdleTime, config.HealthCheckPeriod)
			}
			if err := store.Ping(ctx); err != nil {
				t.Fatalf("ping: %v", err)
			}
		})
	}
}

func TestEnsureSchemaCreatesSchemaAndIsIdempotent(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	for i := range 2 {
		if err := store.EnsureSchema(ctx); err != nil {
			t.Fatalf("ensure schema run %d: %v", i+1, err)
		}
	}

	var relations []string
	rows, err := store.pool.Query(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r', 'i')
		ORDER BY c.relname`, store.schema)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		relations = append(relations, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"build_records",
		"build_records_git_tag_idx",
		"build_records_identity_unique",
		"build_records_measurement_idx",
		"build_records_pkey",
		"revocations",
		"revocations_build_record_id_key",
		"revocations_pkey",
	}
	if strings.Join(relations, ",") != strings.Join(want, ",") {
		t.Fatalf("relations = %v, want %v", relations, want)
	}
}

func TestEnsureSchemaKeepsExistingRows(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	revocation, _, _ := store.createRevocation(t, revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour)))

	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatalf("re-apply schema: %v", err)
	}
	found, err := store.FindByTag(context.Background(), created.Statement.GitTag)
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, "build_records", buildRecordIDs(found), []int64{created.ID})
	if found[0].Revocation == nil || found[0].Revocation.ID != revocation.ID {
		t.Fatalf("revocation lost after re-applying schema: %+v", found[0].Revocation)
	}
}

func TestCreateBuildRecord(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	statement := testStatement(1, 1, 1, baseTime)

	created, payload, signature := store.createBuildRecord(t, statement)
	if created.ID <= 0 || created.CreatedAt.IsZero() {
		t.Fatalf("id/created_at not populated: %+v", created)
	}
	assertStatementEqual(t, created.Statement, statement)
	if created.Proof != store.proof(payload, signature) {
		t.Fatalf("proof = %+v", created.Proof)
	}
	if created.Revoked || created.Revocation != nil {
		t.Fatalf("new build record is revoked: %+v", created)
	}

	// Any one differing identity field makes a distinct Build Record.
	variants := []buildrecord.BuildRecordStatement{
		testStatement(2, 1, 1, baseTime),
		testStatement(1, 2, 1, baseTime),
		testStatement(1, 1, 2, baseTime),
	}
	other := statement
	other.Repository = "https://github.com/verirelay/veriprov"
	variants = append(variants, other)
	for _, variant := range variants {
		next, _, _ := store.createBuildRecord(t, variant)
		if next.ID <= created.ID {
			t.Fatalf("id %d not after %d", next.ID, created.ID)
		}
	}
}

func TestCreateBuildRecordConflict(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	statement := testStatement(1, 1, 1, baseTime)
	store.createBuildRecord(t, statement)

	// committed_at is not part of the identity, so a re-sign still conflicts.
	duplicate := statement
	duplicate.CommittedAt = baseTime.Add(time.Hour)
	payload, err := buildrecord.CanonicalBuildRecord(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateBuildRecord(context.Background(), duplicate, payload, ed25519.Sign(store.privateKey, payload))
	if !errors.Is(err, buildrecord.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

func TestCreateBuildRecordReturnsOtherDatabaseErrors(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	_, err := store.CreateBuildRecord(context.Background(), testStatement(1, 1, 1, baseTime), []byte("{}"), make([]byte, 63))
	if errors.Is(err, buildrecord.ErrConflict) {
		t.Fatal("check violation reported as conflict")
	}
	assertPgErrorCode(t, err, "23514")
}

func TestFindBuildRecords(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	ctx := context.Background()

	a, aPayload, aSignature := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	b, _, _ := store.createBuildRecord(t, testStatement(2, 1, 2, baseTime.Add(time.Hour)))
	c, _, _ := store.createBuildRecord(t, testStatement(1, 2, 1, baseTime.Add(2*time.Hour)))
	// Same committed_at as c: ties break on id, newest first.
	d, _, _ := store.createBuildRecord(t, testStatement(3, 3, 1, baseTime.Add(2*time.Hour)))

	tests := []struct {
		name  string
		find  func(context.Context, string) ([]buildrecord.BuildRecord, error)
		value string
		want  []int64
	}{
		{name: "tag", find: store.FindByTag, value: a.Statement.GitTag, want: []int64{b.ID, a.ID}},
		{name: "measurement", find: store.FindByMeasurement, value: a.Statement.Measurement, want: []int64{d.ID, c.ID, a.ID}},
		{name: "missing tag", find: store.FindByTag, value: "v9.9.9", want: []int64{}},
		{name: "missing measurement", find: store.FindByMeasurement, value: testMeasurement(99), want: []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := tt.find(ctx, tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if found == nil {
				t.Fatal("result is nil, want empty slice")
			}
			assertIDs(t, tt.name, buildRecordIDs(found), tt.want)
		})
	}

	found, err := store.FindByTag(ctx, a.Statement.GitTag)
	if err != nil {
		t.Fatal(err)
	}
	got := found[1]
	assertStatementEqual(t, got.Statement, a.Statement)
	if got.Proof != store.proof(aPayload, aSignature) {
		t.Fatalf("proof = %+v", got.Proof)
	}
	if !got.CreatedAt.Equal(a.CreatedAt) {
		t.Fatalf("created_at = %s, want %s", got.CreatedAt, a.CreatedAt)
	}
	if got.Revoked || got.Revocation != nil {
		t.Fatalf("unrevoked build record reported as revoked: %+v", got)
	}
}

func TestFindBuildRecordsIncludesRevocation(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	ctx := context.Background()

	revoked, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	kept, _, _ := store.createBuildRecord(t, testStatement(2, 1, 2, baseTime.Add(time.Hour)))
	statement := revocationFor(revoked.Statement, "measurement leaked", baseTime.Add(48*time.Hour))
	revocation, payload, signature := store.createRevocation(t, statement)

	finders := map[string]func() ([]buildrecord.BuildRecord, error){
		"tag": func() ([]buildrecord.BuildRecord, error) { return store.FindByTag(ctx, revoked.Statement.GitTag) },
		"measurement": func() ([]buildrecord.BuildRecord, error) {
			return store.FindByMeasurement(ctx, revoked.Statement.Measurement)
		},
	}
	for name, find := range finders {
		t.Run(name, func(t *testing.T) {
			found, err := find()
			if err != nil {
				t.Fatal(err)
			}
			var got *buildrecord.BuildRecord
			for i := range found {
				switch found[i].ID {
				case revoked.ID:
					got = &found[i]
				case kept.ID:
					if found[i].Revoked || found[i].Revocation != nil {
						t.Fatalf("unrevoked build record reported as revoked: %+v", found[i])
					}
				}
			}
			if got == nil {
				t.Fatalf("revoked build record %d not found in %v", revoked.ID, buildRecordIDs(found))
			}
			if !got.Revoked || got.Revocation == nil {
				t.Fatalf("build record not marked revoked: %+v", got)
			}
			if got.Revocation.ID != revocation.ID || !got.Revocation.CreatedAt.Equal(revocation.CreatedAt) {
				t.Fatalf("revocation = %+v, want %+v", got.Revocation, revocation)
			}
			assertRevocationStatementEqual(t, got.Revocation.Statement, statement)
			if got.Revocation.Proof != store.proof(payload, signature) {
				t.Fatalf("revocation proof = %+v", got.Revocation.Proof)
			}
		})
	}
}

func TestFindBuildRecordsReturnsEveryMatch(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	const records = 150
	for i := range records {
		store.createBuildRecord(t, testStatement(i, 1, i, baseTime.Add(time.Duration(i)*time.Minute)))
	}
	found, err := store.FindByTag(context.Background(), "v1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != records {
		t.Fatalf("len = %d, want %d", len(found), records)
	}
	if found[0].Statement.GitCommit != testCommit(records-1) || found[records-1].Statement.GitCommit != testCommit(0) {
		t.Fatalf("wrong order: first %s, last %s", found[0].Statement.GitCommit, found[records-1].Statement.GitCommit)
	}
}

func TestSeveralBuildRecordsPerTag(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	ctx := context.Background()

	// Release registers one Build Record per Launch Measurement, all with the same commit and tag.
	var created []buildrecord.BuildRecord
	for measurement := range 5 {
		record, _, _ := store.createBuildRecord(t, testStatement(1, 1, measurement, baseTime))
		created = append(created, record)
	}
	tag := created[0].Statement.GitTag
	found, err := store.FindByTag(ctx, tag)
	if err != nil {
		t.Fatal(err)
	}
	assertIDs(t, "tag", buildRecordIDs(found), []int64{created[4].ID, created[3].ID, created[2].ID, created[1].ID, created[0].ID})
	for _, record := range created {
		found, err := store.FindByMeasurement(ctx, record.Statement.Measurement)
		if err != nil {
			t.Fatal(err)
		}
		assertIDs(t, "measurement", buildRecordIDs(found), []int64{record.ID})
	}

	// Each Build Record of the tag is revoked on its own.
	revoked := created[2]
	store.createRevocation(t, revocationFor(revoked.Statement, "compromised", baseTime.Add(time.Hour)))
	found, err = store.FindByTag(ctx, tag)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range found {
		if item.Revoked != (item.ID == revoked.ID) {
			t.Fatalf("build record %d: revoked = %t", item.ID, item.Revoked)
		}
	}
	for _, record := range created {
		if record.ID != revoked.ID {
			store.createRevocation(t, revocationFor(record.Statement, "compromised", baseTime.Add(time.Hour)))
		}
	}
	found, err = store.FindByTag(ctx, tag)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range found {
		if !item.Revoked {
			t.Fatalf("build record %d not revoked", item.ID)
		}
	}
}

func TestTimesAreUTC(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	assertUTC(t, "created created_at", created.CreatedAt)
	revocation, _, _ := store.createRevocation(t, revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour)))
	assertUTC(t, "revocation created_at", revocation.CreatedAt)

	found, err := store.FindByTag(context.Background(), created.Statement.GitTag)
	if err != nil {
		t.Fatal(err)
	}
	got := found[0]
	assertUTC(t, "committed_at", got.Statement.CommittedAt)
	assertUTC(t, "created_at", got.CreatedAt)
	assertUTC(t, "revoked_at", got.Revocation.Statement.RevokedAt)
	assertUTC(t, "revocation created_at", got.Revocation.CreatedAt)
}

func TestCreateRevocation(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	statement := revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour))

	revocation, payload, signature := store.createRevocation(t, statement)
	if revocation.ID <= 0 || revocation.CreatedAt.IsZero() {
		t.Fatalf("id/created_at not populated: %+v", revocation)
	}
	assertRevocationStatementEqual(t, revocation.Statement, statement)
	if revocation.Proof != store.proof(payload, signature) {
		t.Fatalf("proof = %+v", revocation.Proof)
	}
}

func TestCreateRevocationNotFound(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))

	// Revocations must match the whole identity, not just one field.
	base := revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour))
	mutations := map[string]func(*buildrecord.RevocationStatement){
		"repository":  func(s *buildrecord.RevocationStatement) { s.Repository = "https://github.com/verirelay/veriprov" },
		"commit":      func(s *buildrecord.RevocationStatement) { s.GitCommit = testCommit(2) },
		"tag":         func(s *buildrecord.RevocationStatement) { s.GitTag = "v1.0.2" },
		"measurement": func(s *buildrecord.RevocationStatement) { s.Measurement = testMeasurement(2) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			statement := base
			mutate(&statement)
			_, err := store.CreateRevocation(context.Background(), statement, []byte("{}"), make([]byte, 64))
			if !errors.Is(err, buildrecord.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
		})
	}

	found, err := store.FindByTag(context.Background(), created.Statement.GitTag)
	if err != nil {
		t.Fatal(err)
	}
	if found[0].Revoked {
		t.Fatalf("build record revoked by a non-matching revocation: %+v", found[0].Revocation)
	}
}

func TestCreateRevocationConflict(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	first, _, _ := store.createRevocation(t, revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour)))

	second := revocationFor(created.Statement, "duplicate", baseTime.Add(2*time.Hour))
	payload, err := buildrecord.CanonicalRevocation(second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateRevocation(context.Background(), second, payload, ed25519.Sign(store.privateKey, payload))
	if !errors.Is(err, buildrecord.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}

	found, err := store.FindByTag(context.Background(), created.Statement.GitTag)
	if err != nil {
		t.Fatal(err)
	}
	if got := found[0].Revocation; got == nil || got.ID != first.ID || got.Statement.Reason != "compromised" {
		t.Fatalf("original revocation replaced: %+v", got)
	}
}

func TestCreateRevocationReturnsOtherDatabaseErrors(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, _, _ := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	statement := revocationFor(created.Statement, "compromised", baseTime.Add(time.Hour))

	_, err := store.CreateRevocation(context.Background(), statement, []byte("{}"), make([]byte, 63))
	if errors.Is(err, buildrecord.ErrConflict) {
		t.Fatal("check violation reported as conflict")
	}
	assertPgErrorCode(t, err, "23514")

	// The failed insert must roll back so a valid retry still succeeds.
	store.createRevocation(t, statement)
}

func TestClosedStoreReturnsErrors(t *testing.T) {
	t.Parallel()
	store := newStoreWithSchema(t)
	created, payload, signature := store.createBuildRecord(t, testStatement(1, 1, 1, baseTime))
	store.Close()
	ctx := context.Background()

	if err := store.Ping(ctx); err == nil {
		t.Error("Ping succeeded on closed store")
	}
	if err := store.EnsureSchema(ctx); err == nil || !strings.Contains(err.Error(), "apply schema") {
		t.Errorf("EnsureSchema error = %v", err)
	}
	if _, err := store.CreateBuildRecord(ctx, testStatement(2, 2, 2, baseTime), payload, signature); err == nil || errors.Is(err, buildrecord.ErrConflict) {
		t.Errorf("CreateBuildRecord error = %v", err)
	}
	if _, err := store.FindByTag(ctx, created.Statement.GitTag); err == nil {
		t.Error("FindByTag succeeded on closed store")
	}
	if _, err := store.FindByMeasurement(ctx, created.Statement.Measurement); err == nil {
		t.Error("FindByMeasurement succeeded on closed store")
	}
	revocation := revocationFor(created.Statement, "compromised", baseTime)
	if _, err := store.CreateRevocation(ctx, revocation, payload, signature); err == nil || errors.Is(err, buildrecord.ErrNotFound) {
		t.Errorf("CreateRevocation error = %v", err)
	}
}
