package store

import (
	"os"
	"path/filepath"

	"github.com/hadefication/warden/internal/envfile"
)

// OpenSecrets opens $HOME/.secrets.
//
// The file is shell syntax that ~/.zshrc sources, but Warden parses it as plain
// text and never executes it. Sourcing would run any command substitution the
// file contains, turning a read into arbitrary code execution.
func OpenSecrets(home string) (Store, error) {
	path := filepath.Join(home, ".secrets")
	f, err := envfile.Parse(path, envfile.Options{AllowExport: true})
	if os.IsNotExist(err) {
		return nil, ErrNoFile
	}
	if err != nil {
		return nil, err
	}
	return &fileStore{f: f}, nil
}
