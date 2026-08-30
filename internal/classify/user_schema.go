package classify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	userSchemaDirMode  = 0o700
	userSchemaFileMode = 0o600
)

// UserSchemaPath is the central classification registry for a home directory.
// It records project paths, key names, and classes, never environment values.
func UserSchemaPath(home string) string {
	return filepath.Join(home, ".warden", "schema")
}

// userRegistry is the on-disk JSON shape: canonical project root, then key,
// then the class name. Keeping the raw strings at this boundary makes invalid
// files rejectable rather than silently coercing an unknown value.
type userRegistry map[string]map[string]string

// LoadUserSchema reads the central registry entry for projectDir. A missing
// registry or an unlisted project returns nil without error.
func LoadUserSchema(home, projectDir string) (*Schema, error) {
	project, err := CanonicalProjectRoot(projectDir)
	if err != nil {
		return nil, err
	}
	registry, exists, err := loadUserRegistry(UserSchemaPath(home))
	if err != nil || !exists {
		return nil, err
	}
	raw, ok := registry[project]
	if !ok {
		return nil, nil
	}
	return schemaFromStrings(UserSchemaPath(home), raw)
}

// SetUserClass records key's class under projectDir in the central registry.
// It preserves every other project and key and returns the registry path.
func SetUserClass(home, projectDir, key string, class Class) (string, error) {
	project, err := CanonicalProjectRoot(projectDir)
	if err != nil {
		return "", err
	}
	path := UserSchemaPath(home)
	if err := ensureUserSchemaDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	registry, exists, err := loadUserRegistry(path)
	if err != nil {
		return "", err
	}
	if !exists {
		registry = userRegistry{}
	}
	if registry[project] == nil {
		registry[project] = map[string]string{}
	}
	registry[project][key] = class.String()
	if err := saveUserRegistry(path, registry); err != nil {
		return "", err
	}
	return path, nil
}

// CanonicalProjectRoot returns the stable project key used in the registry.
func CanonicalProjectRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving project path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolving project path %s: %w", abs, err)
	}
	return filepath.Clean(canonical), nil
}

func loadUserRegistry(path string) (userRegistry, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("reading %s: refusing a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("reading %s: not a regular file", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	var registry userRegistry
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&registry); err != nil {
		return nil, false, fmt.Errorf("parsing %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON documents")
		}
		return nil, false, fmt.Errorf("parsing %s: %w", path, err)
	}
	if registry == nil {
		return nil, false, fmt.Errorf("parsing %s: want a JSON object", path)
	}
	for project, raw := range registry {
		if raw == nil {
			return nil, false, fmt.Errorf("%s: project %q must map keys to classes", path, project)
		}
		if _, err := schemaFromStrings(path, raw); err != nil {
			return nil, false, err
		}
	}
	return registry, true, nil
}

func schemaFromStrings(path string, raw map[string]string) (*Schema, error) {
	s := &Schema{entries: map[string]Class{}}
	for key, value := range raw {
		switch value {
		case "public":
			s.entries[key] = Public
		case "secret":
			s.entries[key] = Secret
		default:
			return nil, fmt.Errorf("%s: %s has class %q, want \"public\" or \"secret\"", path, key, value)
		}
	}
	return s, nil
}

func ensureUserSchemaDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, userSchemaDirMode); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("checking %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("using %s: refusing a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("using %s: not a directory", dir)
	}
	return nil
}

func saveUserRegistry(path string, registry userRegistry) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".schema-*")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(userSchemaFileMode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(registry); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
