package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ShareStore supplies Shamir unseal shares. Implementations must not include
// secret contents in errors: errors may be sent to notification services.
type ShareStore interface {
	Load(context.Context) ([]string, error)
}

type configShareStore struct{ shares []string }

func (s configShareStore) Load(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(s.shares) == 0 {
		return nil, errors.New("no tokens found in config")
	}
	return append([]string(nil), s.shares...), nil
}

// Use a deliberately restricted subset of systemd credential IDs. Never accept
// paths or enumerate the directory, which may contain unrelated credentials.
var credentialID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

const maxShareSize = 16 * 1024

type systemdShareStore struct{ names []string }

func (c *Config) shareStore() (ShareStore, error) {
	switch c.Storage.Provider {
	case "", "config":
		if len(c.Storage.Credentials) != 0 {
			return nil, errors.New("storage.credentials requires the systemd provider")
		}
		return configShareStore{shares: c.Tokens}, nil
	case "systemd":
		if len(c.Tokens) != 0 {
			return nil, errors.New("systemd storage cannot be combined with unseal_tokens or --tokens")
		}
		if len(c.Storage.Credentials) == 0 {
			return nil, errors.New("systemd storage requires credential names")
		}
		seen := make(map[string]bool)
		for _, name := range c.Storage.Credentials {
			if !credentialID.MatchString(name) {
				return nil, errors.New("invalid systemd credential name")
			}
			if seen[name] {
				return nil, errors.New("duplicate systemd credential name")
			}
			seen[name] = true
		}
		return systemdShareStore{names: append([]string(nil), c.Storage.Credentials...)}, nil
	default:
		return nil, errors.New("unknown share storage provider")
	}
}

func (s systemdShareStore) Load(ctx context.Context) ([]string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, errors.New("systemd storage requires an absolute CREDENTIALS_DIRECTORY")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("cannot open systemd credentials directory")
	}
	defer root.Close()
	shares := make([]string, 0, len(s.names))
	for _, name := range s.names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		share, err := readCredential(root, name)
		if err != nil {
			return nil, fmt.Errorf("systemd credential %q: %w", name, err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func readCredential(root *os.Root, name string) (string, error) {
	// Lstat rejects symlinks and special files before opening; OpenRoot also
	// prevents path escape. The directory is supplied and managed by systemd.
	info, err := root.Lstat(name)
	if err != nil {
		return "", errors.New("cannot access credential")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("credential must be a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return "", errors.New("cannot open credential")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxShareSize+1))
	if err != nil {
		return "", errors.New("cannot read credential")
	}
	if len(b) > maxShareSize {
		return "", errors.New("credential exceeds size limit")
	}
	// Accept the trailing newline produced by interactive provisioning, but
	// require exactly one nonempty share, never YAML or a list of shares.
	share := strings.TrimSpace(string(b))
	if share == "" || strings.ContainsAny(share, " \t\r\n\x00") {
		return "", errors.New("credential must contain one nonempty share without whitespace")
	}
	return share, nil
}
