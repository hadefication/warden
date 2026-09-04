// Package exposure records which keys were written through a channel that put
// their value somewhere durable — a command line, and so shell history and argv.
//
// It stores key names and project paths. It never stores a value: this file
// exists to say "that credential is burned, rotate it", and a warning that
// carried a second copy of the secret would be worse than the exposure it warns
// about.
//
// The record is what makes `--exposed` honest. A message printed once scrolls
// away; this survives until the key is rewritten through a channel that does not
// expose it, and doctor reports it in the meantime.
package exposure

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

// registry is scope (canonical project root, or the secrets file path for
// global) to the key names burned under it.
type registry map[string][]string

// Path is the record's location for a home directory.
func Path(home string) string {
	return filepath.Join(home, ".warden", "exposed")
}

// Record marks key as exposed under scope. Recording an already-marked key
// changes nothing.
func Record(home, scope, key string) error {
	reg, err := load(home)
	if err != nil {
		return err
	}
	if slices.Contains(reg[scope], key) {
		return nil
	}
	reg[scope] = append(reg[scope], key)
	return save(home, reg)
}

// Clear removes key's mark under scope, and is a no-op if it carried none.
//
// Every channel that does not expose a value calls this, because once the key
// holds something the caller never handled, the old warning is stale. A warning
// that cannot be cleared is one people learn to scroll past.
func Clear(home, scope, key string) error {
	reg, err := load(home)
	if err != nil {
		return err
	}
	keys, ok := reg[scope]
	if !ok {
		return nil
	}
	i := slices.Index(keys, key)
	if i < 0 {
		return nil
	}
	reg[scope] = slices.Delete(keys, i, i+1)
	if len(reg[scope]) == 0 {
		delete(reg, scope)
	}
	return save(home, reg)
}

// List returns the keys marked under scope, in the order they were recorded.
// A missing record is the normal state and returns nothing.
func List(home, scope string) ([]string, error) {
	reg, err := load(home)
	if err != nil {
		return nil, err
	}
	return reg[scope], nil
}

func load(home string) (registry, error) {
	b, err := os.ReadFile(Path(home))
	if errors.Is(err, os.ErrNotExist) {
		return registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	reg := registry{}
	if err := json.Unmarshal(b, &reg); err != nil {
		return nil, err
	}
	return reg, nil
}

func save(home string, reg registry) error {
	path := Path(home)
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), fileMode)
}
