package classify

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/webteractive/warden/internal/envfile"
)

// SchemaFilename is the per-project override file.
const SchemaFilename = ".env.schema"

// Schema holds explicit per-key classifications, for the cases where the
// built-in heuristics get it wrong. Most projects will never need one.
//
// Format is one KEY=class per line, class being "public" or "secret":
//
//	MY_PUBLIC_KEY=public
//	INTERNAL_MODE=secret
//
// A schema cannot waive value-shape detection — see Classify.
type Schema struct {
	entries map[string]Class
}

// LoadSchema reads dir/.env.schema. A missing file is not an error: it returns
// (nil, nil), and a nil *Schema is safe to pass to Classify.
func LoadSchema(dir string) (*Schema, error) {
	path := filepath.Join(dir, SchemaFilename)
	f, err := envfile.Parse(path, envfile.Options{})
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s := &Schema{entries: map[string]Class{}}
	for _, key := range f.Keys() {
		raw, _ := f.Get(key)
		switch raw {
		case "public":
			s.entries[key] = Public
		case "secret":
			s.entries[key] = Secret
		default:
			return nil, fmt.Errorf("%s: %s has class %q, want \"public\" or \"secret\"", path, key, raw)
		}
	}
	return s, nil
}

// schemaHeader opens a schema warden creates itself, so the file explains its
// own format to whoever reads it next.
const schemaHeader = "# warden classification overrides — one KEY=public|secret per line.\n"

// schemaMode is deliberately looser than the 0600 an .env warrants: a schema
// records class names and never values, and is commonly committed.
const schemaMode = 0o644

// SetClass records an explicit classification for key in dir/.env.schema and
// returns the path written. A missing file is created with a header; an existing
// one keeps its comments, its layout, and every entry SetClass did not touch.
//
// Recording an override here does not make it decisive: Classify still puts
// value shape ahead of the schema, so an entry declaring a live credential
// public has no effect. Callers who care should check ShapeRule first.
func SetClass(dir, key string, c Class) (string, error) {
	path := filepath.Join(dir, SchemaFilename)

	// O_EXCL rather than a Stat-then-write: Stat follows symlinks and reports
	// IsNotExist for a dangling one, so writing after it would follow the link to
	// its target. O_EXCL refuses to create through a symlink at all, and reports
	// EEXIST for a schema that already exists — which is the path that carries on
	// below.
	switch fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, schemaMode); {
	case err == nil:
		_, werr := fh.WriteString(schemaHeader)
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
	case !os.IsExist(err):
		return "", err
	}

	f, err := envfile.Parse(path, envfile.Options{})
	if err != nil {
		return "", err
	}
	f.Set(key, c.String())
	if err := f.Save(); err != nil {
		return "", err
	}
	return path, nil
}

// Lookup returns an explicit override for key, if one is declared.
func (s *Schema) Lookup(key string) (Class, bool) {
	if s == nil {
		return Public, false
	}
	c, ok := s.entries[key]
	return c, ok
}
