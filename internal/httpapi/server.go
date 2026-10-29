package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/verirelay/registry/internal/buildrecord"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxRequestBody = 1 << 20
	requestTimeout = 10 * time.Second
)

type Server struct {
	store           buildrecord.Store
	publicKey       ed25519.PublicKey
	apiPasswordHash []byte
	logger          *slog.Logger
	handler         http.Handler
}

type signedBuildRecordRequest struct {
	Statement buildrecord.BuildRecordStatement `json:"statement"`
	Signature string                           `json:"signature"`
}

type signedRevocationRequest struct {
	Statement buildrecord.RevocationStatement `json:"statement"`
	Signature string                          `json:"signature"`
}

type listResponse struct {
	Items []buildrecord.BuildRecord `json:"items"`
	Count int                       `json:"count"`
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func New(store buildrecord.Store, publicKey ed25519.PublicKey, apiPasswordHash string, logger *slog.Logger) (*Server, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	if _, err := bcrypt.Cost([]byte(apiPasswordHash)); err != nil {
		return nil, errors.New("API_PWD_HASH must be a valid bcrypt hash")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{store: store, publicKey: publicKey, apiPasswordHash: []byte(apiPasswordHash), logger: logger}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /v1/public-key", s.publicKeyInfo)
	mux.Handle("POST /v1/build-records", s.requireAPIKey(http.HandlerFunc(s.createBuildRecord)))
	mux.HandleFunc("GET /v1/build-records/by-tag/{tag...}", s.byTag)
	mux.HandleFunc("GET /v1/build-records/by-measurement/{digest}", s.byMeasurement)
	mux.Handle("POST /v1/revocations", s.requireAPIKey(http.HandlerFunc(s.createRevocation)))
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		r = r.WithContext(ctx)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic serving request", "error", recovered, "method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
			s.logger.Info("request completed", "method", r.Method, "path", r.URL.Path, "duration", time.Since(started))
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-API-Key")
		if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
			provided = strings.TrimPrefix(authorization, "Bearer ")
		}
		if bcrypt.CompareHashAndPassword(s.apiPasswordHash, []byte(provided)) != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid API key is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) publicKeyInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]string{
		"algorithm":  "ed25519",
		"key_id":     buildrecord.KeyID(s.publicKey),
		"public_key": base64.RawURLEncoding.EncodeToString(s.publicKey),
	})
}

func (s *Server) createBuildRecord(w http.ResponseWriter, r *http.Request) {
	var request signedBuildRecordRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	payload, err := buildrecord.CanonicalBuildRecord(request.Statement)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_statement", err.Error())
		return
	}
	signature, err := buildrecord.Verify(s.publicKey, payload, request.Signature)
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid_signature", err.Error())
		return
	}
	created, err := s.store.CreateBuildRecord(r.Context(), request.Statement, payload, signature)
	if errors.Is(err, buildrecord.ErrConflict) {
		writeError(w, http.StatusConflict, "build_record_exists", "this build identity already exists")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/v1/build-records/by-measurement/%s", created.Statement.Measurement))
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) createRevocation(w http.ResponseWriter, r *http.Request) {
	var request signedRevocationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	payload, err := buildrecord.CanonicalRevocation(request.Statement)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_statement", err.Error())
		return
	}
	signature, err := buildrecord.Verify(s.publicKey, payload, request.Signature)
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid_signature", err.Error())
		return
	}
	created, err := s.store.CreateRevocation(r.Context(), request.Statement, payload, signature)
	if errors.Is(err, buildrecord.ErrNotFound) {
		writeError(w, http.StatusNotFound, "build_record_not_found", "the referenced build record does not exist")
		return
	}
	if errors.Is(err, buildrecord.ErrConflict) {
		writeError(w, http.StatusConflict, "revocation_exists", "this build record is already revoked")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) byTag(w http.ResponseWriter, r *http.Request) {
	value := r.PathValue("tag")
	if err := buildrecord.ValidateTag(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tag", err.Error())
		return
	}
	s.find(w, r, func(ctx context.Context) ([]buildrecord.BuildRecord, error) {
		return s.store.FindByTag(ctx, value)
	})
}

func (s *Server) byMeasurement(w http.ResponseWriter, r *http.Request) {
	value := r.PathValue("digest")
	if err := buildrecord.ValidateMeasurement(value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_measurement", err.Error())
		return
	}
	s.find(w, r, func(ctx context.Context) ([]buildrecord.BuildRecord, error) {
		return s.store.FindByMeasurement(ctx, value)
	})
}

func (s *Server) find(w http.ResponseWriter, r *http.Request, lookup func(context.Context) ([]buildrecord.BuildRecord, error)) {
	items, err := lookup(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	// Every Build Record carries its revocation state, so caches must revalidate.
	w.Header().Set("Cache-Control", "no-cache")
	writeJSON(w, http.StatusOK, listResponse{Items: items, Count: len(items)})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "error", err, "method", r.Method, "path", r.URL.Path)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

// decodeJSON decodes the request body, which must be exactly one JSON object,
// into destination. At every depth it rejects duplicate keys and keys that do
// not exactly name a field of destination's type, including keys that match
// one only case-insensitively, as encoding/json alone would accept.
func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	if token, err := scanner.Token(); err != nil || token != json.Delim('{') {
		return errors.New("request body must contain one JSON object")
	}
	if err := checkKeys(scanner, "", reflect.TypeOf(destination)); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

// checkKeys consumes the rest of the object whose opening brace decoder has
// just returned, checking its keys against the fields of t at every depth.
func checkKeys(decoder *json.Decoder, path string, t reflect.Type) error {
	fields := jsonFields(t)
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, _ := token.(string) // object keys are always strings
		key := name
		if path != "" {
			key = path + "." + name
		}
		if seen[name] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[name] = true
		fieldType, known := fields[name]
		if !known {
			return fmt.Errorf("unknown field %q", key)
		}
		if err := checkValue(decoder, key, fieldType); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func checkValue(decoder *json.Decoder, path string, t reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		return checkKeys(decoder, path, t)
	case json.Delim('['):
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		for decoder.More() {
			if err := checkValue(decoder, path+"[]", t); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	}
	return nil
}

// jsonFields maps the JSON names of t's fields to their types, as
// encoding/json names them. A type that is not a struct has no fields.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	fields := make(map[string]reflect.Type)
	if t.Kind() != reflect.Struct {
		return fields
	}
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if !field.IsExported() || tag == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	response := errorResponse{}
	response.Error.Code = code
	response.Error.Message = message
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
