package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hadefication/warden/internal/secret"
)

const (
	headerMagic   = "warden-vault"
	headerVersion = "v1"
	// docVersion is the schema of the JSON document under the seal.
	docVersion = 1
	// saltLen and keyLen are both 32: a 256-bit salt and an AES-256 key.
	saltLen = 32
	keyLen  = 32
)

// header is the plaintext first line. It says how to unseal the file and
// nothing about what is inside — entry names included, which is why they are
// under the seal rather than beside it.
type header struct {
	Mode Mode
	Salt []byte // ModeArgon2id only
}

// renderHeader writes the header line. The salt field is "-" when unused rather
// than empty, so the line always has four fields and a truncated write is
// detectable.
func renderHeader(h header) string {
	salt := "-"
	if len(h.Salt) > 0 {
		salt = base64.StdEncoding.EncodeToString(h.Salt)
	}
	return fmt.Sprintf("%s %s %s %s", headerMagic, headerVersion, h.Mode, salt)
}

// parseHeader reads the header line, refusing anything it does not fully
// understand rather than guessing. A vault warden cannot read is left alone —
// the same stance hook --install takes toward an unparseable settings.json.
func parseHeader(line string) (header, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 4 || fields[0] != headerMagic {
		return header{}, fmt.Errorf("%w: unrecognised header", ErrBadFormat)
	}
	if fields[1] != headerVersion {
		return header{}, fmt.Errorf(
			"%w: this file is %s and this warden understands %s — upgrade warden rather than "+
				"letting it rewrite a vault it cannot read",
			ErrBadFormat, fields[1], headerVersion)
	}

	h := header{Mode: Mode(fields[2])}
	switch h.Mode {
	case ModeKeyring, ModeArgon2id:
	default:
		return header{}, fmt.Errorf("%w: unknown key mode %q", ErrBadFormat, fields[2])
	}

	if fields[3] != "-" {
		salt, err := base64.StdEncoding.DecodeString(fields[3])
		if err != nil {
			return header{}, fmt.Errorf("%w: the salt is not valid base64", ErrBadFormat)
		}
		h.Salt = salt
	}
	if h.Mode == ModeArgon2id && len(h.Salt) == 0 {
		return header{}, fmt.Errorf("%w: argon2id mode with no salt", ErrBadFormat)
	}
	return h, nil
}

// wireEntry is the on-disk shape of an Entry.
//
// It exists for one reason: secret.Secret.MarshalJSON renders "<redacted>", so
// encoding an Entry directly would write the redaction marker into the vault as
// the credential — and nothing would look wrong until a push handed a project
// that string. The conversion below is the single place a vault value is
// exposed, and format_test.go asserts the round trip on a marker value.
type wireEntry struct {
	Name    string     `json:"name"`
	Key     string     `json:"key"`
	Value   string     `json:"value"`
	Created time.Time  `json:"created"`
	Expires *time.Time `json:"expires,omitempty"`
}

type document struct {
	Version int         `json:"version"`
	Entries []wireEntry `json:"entries"`
}

// sealDoc encodes entries and seals them under key. The output is nonce
// followed by ciphertext.
func sealDoc(key []byte, entries []Entry) ([]byte, error) {
	doc := document{Version: docVersion, Entries: make([]wireEntry, 0, len(entries))}
	for _, e := range entries {
		w := wireEntry{
			Name:    e.Name,
			Key:     e.Key,
			Value:   e.Value.Expose(),
			Created: e.Created,
		}
		if !e.Permanent() {
			d := e.Expires
			w.Expires = &d
		}
		doc.Entries = append(doc.Entries, w)
	}

	plain, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encoding the vault: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating a nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// openDoc unseals a blob produced by sealDoc.
func openDoc(key, blob []byte) ([]Entry, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: the file is too short to contain a nonce", ErrUndecryptable)
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Authentication failure means tampering or the wrong key, and there is
		// no way to tell which. Neither is a reason to guess.
		return nil, fmt.Errorf(
			"%w: authentication failed — the file was modified, or the master key is not the one "+
				"it was sealed with", ErrUndecryptable)
	}

	var doc document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("%w: the decrypted contents are not a vault document", ErrBadFormat)
	}
	if doc.Version != docVersion {
		return nil, fmt.Errorf("%w: document version %d", ErrBadFormat, doc.Version)
	}

	entries := make([]Entry, 0, len(doc.Entries))
	for _, w := range doc.Entries {
		e := Entry{
			Name:    w.Name,
			Key:     w.Key,
			Value:   secret.Secret(w.Value),
			Created: w.Created,
		}
		if w.Expires != nil {
			e.Expires = *w.Expires
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("%w: the master key is %d bytes, want %d", ErrUndecryptable, len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUndecryptable, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUndecryptable, err)
	}
	return gcm, nil
}
