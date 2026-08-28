// Package store locates configuration files and hands out their values.
//
// Every value leaves this package as a secret.Secret regardless of whether the
// key is sensitive. Deciding what may be revealed is internal/classify's job and
// revealing it is internal/query's job; keeping that decision out of here means
// no code path can reach a raw value without going through a classification.
package store

import (
	"errors"

	"github.com/webteractive/warden/internal/secret"
)

// ErrNoFile means no backing file was found.
var ErrNoFile = errors.New("no env file found")

// Store is a set of key/value configuration backed by a file.
type Store interface {
	// Path is the backing file's location, suitable for showing a user.
	Path() string
	// Keys lists assigned keys in file order.
	Keys() []string
	// Get returns the value for key, wrapped so it cannot be printed.
	Get(key string) (secret.Secret, bool)
	// Set writes key = value, preserving the rest of the file.
	Set(key, value string) error
	// Unset removes every assignment of key and reports how many it removed.
	Unset(key string) (int, error)
}
