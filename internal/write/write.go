// Package write is the only path that modifies configuration.
//
// Public keys are written directly. Secret keys are written only through a
// prompt.Prompter, so the value arrives from the user rather than from the
// caller — which is what keeps an agent from ever handling it.
package write

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/hadefication/warden/internal/classify"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
	"github.com/hadefication/warden/internal/secret"
	"github.com/hadefication/warden/internal/store"
)

// ErrSecretKey means the write was refused because the key, or the value
// offered for it, is sensitive.
var ErrSecretKey = errors.New("key is secret — use set --secret")

// W is an open, writable view of one store.
type W struct {
	st  store.Store
	sch *classify.Schema
	p   prompt.Prompter
}

// Open resolves the scope and attaches the prompter used for secret writes.
func Open(sc query.Scope, p prompt.Prompter) (*W, error) {
	w := &W{p: p}
	var err error
	if sc.Global {
		w.st, err = store.OpenSecrets(sc.Home)
	} else {
		w.st, err = store.OpenDotenv(sc.Dir)
	}
	if err != nil {
		return nil, err
	}
	if !sc.Global {
		w.sch, err = classify.LoadSchema(filepath.Dir(w.st.Path()))
		if err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Path is the backing file.
func (w *W) Path() string { return w.st.Path() }

// SetPublic writes a value directly. It refuses if the key is secret, and also
// if the incoming value itself looks like a credential — an innocent key name
// is not permission to store a live API key in the clear.
func (w *W) SetPublic(key, value string) error {
	if w.classOf(key).Class == classify.Secret {
		return fmt.Errorf("%s: %w", key, ErrSecretKey)
	}
	if classify.Classify(key, secret.Secret(value), w.sch).Class == classify.Secret {
		return fmt.Errorf("%s: %w (the value looks like a credential)", key, ErrSecretKey)
	}
	return w.st.Set(key, value)
}

// SetSecret prompts the user and writes what they type. A cancelled prompt
// writes nothing.
func (w *W) SetSecret(key string) error {
	v, err := w.p.AskSecret(key, w.st.Path())
	if err != nil {
		return err
	}
	return w.st.Set(key, v.Expose())
}

func (w *W) classOf(key string) classify.Result {
	v, _ := w.st.Get(key)
	return classify.Classify(key, v, w.sch)
}
