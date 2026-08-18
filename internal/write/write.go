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

// ErrUnwaivableShape means a key could not be made public because its value is a
// recognised credential format. Classify puts shape ahead of the schema, so the
// override would have been inert — this is a refusal rather than a silent no-op.
var ErrUnwaivableShape = errors.New(
	"cannot be made public: its value is a recognised credential format, " +
		"which outranks any override")

// ErrGlobalScope means a reclassification was attempted against ~/.secrets.
// That file holds secrets by definition, so an override there has no legitimate
// use and would only serve to unmask one.
var ErrGlobalScope = errors.New("reclassification is not available in global scope")

// ErrAbsent means the key does not appear in the file at all, so there is
// nothing to remove or empty. Distinct from a key that is present and empty:
// that one has a line to delete.
var ErrAbsent = errors.New("key is not present")

// W is an open, writable view of one store.
type W struct {
	st     store.Store
	sch    *classify.Schema
	p      prompt.Prompter
	global bool
}

// Open resolves the scope and attaches the prompter used for secret writes.
func Open(sc query.Scope, p prompt.Prompter) (*W, error) {
	w := &W{p: p, global: sc.Global}
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

// SchemaPath is where classification overrides for this store live, whether or
// not the file exists yet.
//
// Only meaningful in project scope. Global scope would name ~/.env.schema, which
// nothing reads — Reclassify refuses that scope before it gets here.
func (w *W) SchemaPath() string {
	return filepath.Join(filepath.Dir(w.st.Path()), classify.SchemaFilename)
}

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

// Unset removes every assignment of key and reports how many it removed.
//
// A key holding a value goes through the prompt first. Nothing is revealed by a
// deletion, so the risk being guarded is destruction, not disclosure — the user
// may not be able to recover the value from anywhere else. A key that is absent
// or already empty skips the prompt: there is nothing to lose, and asking anyway
// would train the answer.
func (w *W) Unset(key string) (int, error) {
	v, present := w.st.Get(key)
	if !present {
		return 0, fmt.Errorf("%s: %w", key, ErrAbsent)
	}
	if v.IsSet() {
		if err := w.p.ConfirmAction("remove", key, w.st.Path()); err != nil {
			return 0, err
		}
	}
	return w.st.Unset(key)
}

// Clear empties a key's value while leaving it declared, so it still shows up in
// warden list as declared-but-unset. Same authorisation rule as Unset.
func (w *W) Clear(key string) error {
	v, present := w.st.Get(key)
	if !present {
		return fmt.Errorf("%s: %w", key, ErrAbsent)
	}
	if !v.IsSet() {
		return nil
	}
	if err := w.p.ConfirmAction("clear", key, w.st.Path()); err != nil {
		return err
	}
	return w.st.Set(key, "")
}

// Reclassify records an explicit class for key in the project's .env.schema,
// once the user authorises it through the prompt. Nothing is written if they
// decline.
//
// Two refusals land before the prompt, so the user is never made to authorise
// something that was going to fail anyway:
//
//   - global scope, where an override has no legitimate use;
//   - promoting a credential-shaped value to public, which Classify would
//     override on sight, leaving a schema entry that silently does nothing.
//
// A key that is secret only by *name* is fair game — correcting that is what
// this exists for.
func (w *W) Reclassify(key string, to classify.Class) error {
	if w.global {
		return fmt.Errorf("%s: %w", key, ErrGlobalScope)
	}
	if to == classify.Public {
		v, _ := w.st.Get(key)
		if rule, ok := classify.ShapeRule(v); ok {
			return fmt.Errorf("%s %w (%s)", key, ErrUnwaivableShape, rule)
		}
	}

	dir := filepath.Dir(w.st.Path())

	// Only the loosening direction demands the key be retyped.
	if err := w.p.Confirm(to.String(), key, w.SchemaPath(), to == classify.Public); err != nil {
		return err
	}
	if _, err := classify.SetClass(dir, key, to); err != nil {
		return err
	}

	// Reload so this W stops serving the pre-write classification.
	sch, err := classify.LoadSchema(dir)
	if err != nil {
		return err
	}
	w.sch = sch
	return nil
}

func (w *W) classOf(key string) classify.Result {
	v, _ := w.st.Get(key)
	return classify.Classify(key, v, w.sch)
}
