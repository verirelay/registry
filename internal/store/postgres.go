package store

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verirelay/registry/internal/buildrecord"
)

//go:embed schema.sql
var schemaSQL string

type Postgres struct {
	pool      *pgxpool.Pool
	publicKey ed25519.PublicKey
}

func Open(ctx context.Context, databaseURL string, maxConns int32, publicKey ed25519.PublicKey) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	config.MaxConns = maxConns
	if config.MinConns == 0 && maxConns >= 4 {
		config.MinConns = 2
	}
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 15 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second
	config.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name:  "timestamptz",
			OID:   pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Postgres{pool: pool, publicKey: publicKey}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

func (p *Postgres) EnsureSchema(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, schemaSQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

func (p *Postgres) CreateBuildRecord(ctx context.Context, statement buildrecord.BuildRecordStatement, payload, signature []byte) (buildrecord.BuildRecord, error) {
	const query = `
		INSERT INTO build_records
			(repository, git_commit, git_tag, measurement, committed_at, signed_payload, signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`
	result := buildrecord.BuildRecord{Statement: statement, Proof: buildrecord.NewProof(p.publicKey, payload, signature)}
	err := p.pool.QueryRow(ctx, query,
		statement.Repository, statement.GitCommit, statement.GitTag, statement.Measurement,
		statement.CommittedAt, payload, signature,
	).Scan(&result.ID, &result.CreatedAt)
	if isUniqueViolation(err) {
		return buildrecord.BuildRecord{}, buildrecord.ErrConflict
	}
	if err != nil {
		return buildrecord.BuildRecord{}, err
	}
	return result, nil
}

func (p *Postgres) FindByTag(ctx context.Context, tag string) ([]buildrecord.BuildRecord, error) {
	return p.findBuildRecords(ctx, "m.git_tag = $1", tag)
}

func (p *Postgres) FindByMeasurement(ctx context.Context, measurement string) ([]buildrecord.BuildRecord, error) {
	return p.findBuildRecords(ctx, "m.measurement = $1", measurement)
}

func (p *Postgres) findBuildRecords(ctx context.Context, predicate, value string) ([]buildrecord.BuildRecord, error) {
	query := `
		SELECT
			m.id, m.repository, m.git_commit, m.git_tag, m.measurement, m.committed_at,
			m.signed_payload, m.signature, m.created_at,
			r.id, r.reason, r.revoked_at, r.signed_payload, r.signature, r.created_at
		FROM build_records m
		LEFT JOIN revocations r ON r.build_record_id = m.id
		WHERE ` + predicate + `
		ORDER BY m.committed_at DESC, m.id DESC`
	rows, err := p.pool.Query(ctx, query, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]buildrecord.BuildRecord, 0)
	for rows.Next() {
		item, err := p.scanBuildRecord(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	return results, rows.Err()
}

func (p *Postgres) scanBuildRecord(row pgx.Row) (buildrecord.BuildRecord, error) {
	var (
		result            buildrecord.BuildRecord
		payload           []byte
		signature         []byte
		revocationID      *int64
		reason            *string
		revokedAt         *time.Time
		revocationPayload []byte
		revocationSig     []byte
		revocationCreated *time.Time
	)
	err := row.Scan(
		&result.ID, &result.Statement.Repository, &result.Statement.GitCommit,
		&result.Statement.GitTag, &result.Statement.Measurement, &result.Statement.CommittedAt,
		&payload, &signature, &result.CreatedAt,
		&revocationID, &reason, &revokedAt, &revocationPayload, &revocationSig, &revocationCreated,
	)
	if err != nil {
		return result, err
	}
	result.Statement.Version = buildrecord.BuildRecordVersion
	result.Proof = buildrecord.NewProof(p.publicKey, payload, signature)
	if revocationID != nil {
		result.Revoked = true
		result.Revocation = &buildrecord.Revocation{
			ID: *revocationID,
			Statement: buildrecord.RevocationStatement{
				Version:     buildrecord.RevocationVersion,
				Repository:  result.Statement.Repository,
				GitCommit:   result.Statement.GitCommit,
				GitTag:      result.Statement.GitTag,
				Measurement: result.Statement.Measurement,
				Reason:      *reason,
				RevokedAt:   *revokedAt,
			},
			Proof:     buildrecord.NewProof(p.publicKey, revocationPayload, revocationSig),
			CreatedAt: *revocationCreated,
		}
	}
	return result, nil
}

func (p *Postgres) CreateRevocation(ctx context.Context, statement buildrecord.RevocationStatement, payload, signature []byte) (buildrecord.Revocation, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return buildrecord.Revocation{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const findBuildRecord = `
		SELECT id FROM build_records
		WHERE repository = $1 AND git_commit = $2 AND git_tag = $3 AND measurement = $4`
	var buildRecordID int64
	err = tx.QueryRow(ctx, findBuildRecord,
		statement.Repository, statement.GitCommit, statement.GitTag, statement.Measurement,
	).Scan(&buildRecordID)
	if errors.Is(err, pgx.ErrNoRows) {
		return buildrecord.Revocation{}, buildrecord.ErrNotFound
	}
	if err != nil {
		return buildrecord.Revocation{}, err
	}

	const insert = `
		INSERT INTO revocations (build_record_id, reason, revoked_at, signed_payload, signature)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`
	result := buildrecord.Revocation{Statement: statement, Proof: buildrecord.NewProof(p.publicKey, payload, signature)}
	err = tx.QueryRow(ctx, insert, buildRecordID, statement.Reason, statement.RevokedAt, payload, signature).
		Scan(&result.ID, &result.CreatedAt)
	if isUniqueViolation(err) {
		return buildrecord.Revocation{}, buildrecord.ErrConflict
	}
	if err != nil {
		return buildrecord.Revocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return buildrecord.Revocation{}, err
	}
	return result, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
