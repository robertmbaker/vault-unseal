package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigStoreCompatibility(t *testing.T) {
	for _, provider := range []string{"", "config"} {
		c := Config{Tokens: []string{"first", "second"}, Storage: StorageConfig{Provider: provider}}
		store, err := c.shareStore()
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.Load(context.Background())
		if err != nil || !reflect.DeepEqual(got, c.Tokens) {
			t.Fatalf("unexpected shares or error: %v", err)
		}
		got[0] = "changed"
		if c.Tokens[0] != "first" {
			t.Fatal("provider exposed config slice")
		}
	}
}

func TestStorageValidation(t *testing.T) {
	cases := []Config{
		{Storage: StorageConfig{Provider: "unknown"}},
		{Storage: StorageConfig{Credentials: []string{"key"}}},
		{Storage: StorageConfig{Provider: "systemd"}},
		{Tokens: []string{"secret"}, Storage: StorageConfig{Provider: "systemd", Credentials: []string{"key"}}},
	}
	for _, name := range []string{"../key", "/key", ".", "..", "a/b", "", "a\n", strings.Repeat("x", 256)} {
		cases = append(cases, Config{Storage: StorageConfig{Provider: "systemd", Credentials: []string{name}}})
	}
	cases = append(cases, Config{Storage: StorageConfig{Provider: "systemd", Credentials: []string{"key", "key"}}})
	for i, c := range cases {
		if _, err := c.shareStore(); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestSystemdStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("key1", "first\n")
	write("key2", "second\r\n")
	write("unrelated", "ignored")
	c := Config{Storage: StorageConfig{Provider: "systemd", Credentials: []string{"key2", "key1"}}}
	store, err := c.shareStore()
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"second", "first"}) {
		t.Fatalf("unexpected result: %v", err)
	}
	write("key1", "rotated")
	got, err = store.Load(context.Background())
	if err != nil || got[1] != "rotated" {
		t.Fatal("did not reread credential")
	}
	for _, value := range []string{"", "\n", "secret\nsecret", "secret\x00", strings.Repeat("S", maxShareSize+1)} {
		write("key1", value)
		_, err = store.Load(context.Background())
		if err == nil {
			t.Fatal("accepted malformed credential")
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "SSSS") {
			t.Fatal("error leaked credential")
		}
	}
	if err := os.Remove(filepath.Join(dir, "key1")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(context.Background()); err == nil {
		t.Fatal("accepted missing credential")
	}
	if err := os.Symlink(filepath.Join(dir, "key2"), filepath.Join(dir, "key1")); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(context.Background()); err == nil {
		t.Fatal("accepted symlink")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err = store.Load(context.Background()); err == nil {
		t.Fatal("accepted missing directory")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "relative")
	if _, err = store.Load(context.Background()); err == nil {
		t.Fatal("accepted relative directory")
	}
}

func TestSystemdConfigValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte("test-share"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{AllowSingleNode: true, Nodes: []string{"https://vault.example:8200"}, Storage: StorageConfig{Provider: "systemd", Credentials: []string{"key"}}}
	if err := c.Validate(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if len(c.Tokens) != 0 {
		t.Fatal("systemd shares copied into plaintext config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := c.shareStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
