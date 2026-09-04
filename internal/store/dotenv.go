package store

import (
	"os"
	"path/filepath"

	"github.com/webteractive/warden/internal/envfile"
	"github.com/webteractive/warden/internal/secret"
)

type fileStore struct {
	f *envfile.File
}

func (s *fileStore) Path() string   { return s.f.Path() }
func (s *fileStore) Keys() []string { return s.f.Keys() }

func (s *fileStore) Get(key string) (secret.Secret, bool) {
	v, ok := s.f.Get(key)
	return secret.Secret(v), ok
}

func (s *fileStore) Set(key, value string) error {
	if err := s.f.Set(key, value); err != nil {
		return err
	}
	return s.f.Save()
}

func (s *fileStore) Unset(key string) (int, error) {
	n := s.f.Unset(key)
	if n == 0 {
		// Nothing changed, so there is nothing to write. Saving anyway would
		// rewrite a file of credentials for no reason.
		return 0, nil
	}
	return n, s.f.Save()
}

// OpenDotenv finds the nearest .env at or above startDir and opens it. The walk
// stops at $HOME so a stray .env in the home directory is the furthest it can
// reach, and never escapes into shared parent directories above it.
func OpenDotenv(startDir string) (Store, error) {
	path, err := findUpward(startDir, ".env")
	if err != nil {
		return nil, err
	}
	return OpenDotenvAt(path)
}

// OpenDotenvAt opens a specific .env file.
func OpenDotenvAt(path string) (Store, error) {
	f, err := envfile.Parse(path, envfile.Options{})
	if err != nil {
		return nil, err
	}
	return &fileStore{f: f}, nil
}

// ExampleKeys returns the keys declared by the .env.example sitting beside the
// nearest .env.
func ExampleKeys(startDir string) ([]string, error) {
	envPath, err := findUpward(startDir, ".env")
	if err != nil {
		return nil, err
	}
	examplePath := filepath.Join(filepath.Dir(envPath), ".env.example")
	f, err := envfile.Parse(examplePath, envfile.Options{})
	if os.IsNotExist(err) {
		return nil, ErrNoFile
	}
	if err != nil {
		return nil, err
	}
	return f.Keys(), nil
}

func findUpward(startDir, name string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", err
	}
	home, _ := os.UserHomeDir()
	for {
		candidate := filepath.Join(dir, name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
		if dir == home {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", ErrNoFile
}
