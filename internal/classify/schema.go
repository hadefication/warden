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

// Lookup returns an explicit override for key, if one is declared.
func (s *Schema) Lookup(key string) (Class, bool) {
	if s == nil {
		return Public, false
	}
	c, ok := s.entries[key]
	return c, ok
}
