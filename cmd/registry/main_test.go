package main

import (
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const testReleasePublicKey = "uhbjGjZ0_V75-l-qkQIBmeAmJRHOOLVqlJ0fecoP8G4"

func TestLoadConfig(t *testing.T) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secret"), 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("API_PWD_HASH", string(passwordHash))
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_NAME", "verirelay")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_PWD", "p@ss/word")
	t.Setenv("DB_USER", "verirelay")
	t.Setenv("DB_SSLMODE", "disable")
	t.Setenv("HTTP_ADDR", "127.0.0.1:9000")
	t.Setenv("DB_MAX_CONNS", "64")
	t.Setenv("RELEASE_PUBLIC_KEY", testReleasePublicKey)

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPAddr != "127.0.0.1:9000" || config.MaxConns != 64 {
		t.Fatalf("unexpected config: %#v", config)
	}
	if len(config.PublicKey) != 32 {
		t.Fatal("release public key was not decoded")
	}
	parsedURL, err := url.Parse(config.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	password, _ := parsedURL.User.Password()
	if parsedURL.Host != "localhost:5432" || parsedURL.User.Username() != "verirelay" || password != "p@ss/word" {
		t.Fatalf("unexpected database URL: %s", config.DatabaseURL)
	}
}

func TestLoadConfigRejectsMissingValues(t *testing.T) {
	t.Setenv("API_PWD_HASH", "")
	t.Setenv("DB_HOST", "")
	t.Setenv("DB_NAME", "")
	t.Setenv("DB_PORT", "")
	t.Setenv("DB_PWD", "")
	t.Setenv("DB_USER", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected an error")
	}
}

func TestLoadConfigSSLMode(t *testing.T) {
	t.Setenv("API_PWD_HASH", "$2a$10$abcdefghijklmnopqrstuuJ3eV9kS2i9l2Yq1xQ4h0n1oKpQe3G2i")
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_NAME", "verirelay")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_PWD", "secret")
	t.Setenv("DB_USER", "verirelay")
	t.Setenv("RELEASE_PUBLIC_KEY", testReleasePublicKey)
	for value, want := range map[string]string{"": "verify-full", "disable": "disable", "require": "require"} {
		t.Setenv("DB_SSLMODE", value)
		config, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		parsedURL, err := url.Parse(config.DatabaseURL)
		if err != nil {
			t.Fatal(err)
		}
		if got := parsedURL.Query().Get("sslmode"); got != want {
			t.Fatalf("DB_SSLMODE %q: sslmode = %q, want %q", value, got, want)
		}
	}
	t.Setenv("DB_SSLMODE", "off")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected invalid DB_SSLMODE to be rejected")
	}
}

func TestLoadConfigRejectsInvalidReleasePublicKey(t *testing.T) {
	t.Setenv("API_PWD_HASH", "$2a$10$abcdefghijklmnopqrstuuJ3eV9kS2i9l2Yq1xQ4h0n1oKpQe3G2i")
	t.Setenv("DB_HOST", "localhost")
	t.Setenv("DB_NAME", "verirelay")
	t.Setenv("DB_PORT", "5432")
	t.Setenv("DB_PWD", "secret")
	t.Setenv("DB_USER", "verirelay")
	for _, value := range []string{
		"",
		"not-base64",
		"AAAA",
		"uhbjGjZ0/V75+l+qkQIBmeAmJRHOOLVqlJ0fecoP8G4=",
		"uhbjGjZ0_V75-l-qkQIBmeAmJRHOOLVqlJ0fecoP8G4=",
		"uhbjGjZ0_V75-l-qkQIBmeAmJRHOOLVqlJ0fecoP8G5",
	} {
		t.Setenv("RELEASE_PUBLIC_KEY", value)
		if _, err := loadConfig(); err == nil {
			t.Fatalf("expected an error for RELEASE_PUBLIC_KEY %q", value)
		}
	}
}
