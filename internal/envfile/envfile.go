// Package envfile parses and rewrites dotenv-style files without disturbing
// anything it was not asked to change.
//
// The file is held as a list of lines. Comments, blank lines, ordering, quoting
// style, line endings and trailing-newline state all survive a Save untouched,
// because unmodified lines are written back from their original raw text. Only
// a line whose key was passed to Set is re-rendered.
package envfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrConflictMarkers is returned when the file contains git conflict markers.
// Writing to such a file would corrupt it in ways that are painful to unpick.
var ErrConflictMarkers = errors.New("file contains git conflict markers")

// Options controls dialect differences between .env and ~/.secrets.
type Options struct {
	// AllowExport parses (and preserves) a leading "export " on assignments,
	// which ~/.secrets uses because it is sourced by the shell.
	AllowExport bool
}

type line struct {
	raw      string // authoritative for any line Set has not touched
	key      string // empty for comments and blanks
	value    string // unquoted
	quote    byte   // 0, '\'' or '"' — the original quoting style
	export   bool
	modified bool
}

// File is a parsed env file.
type File struct {
	path    string
	mode    os.FileMode
	lines   []line
	crlf    bool
	finalNL bool
	opts    Options
}

var assignRe = regexp.MustCompile(`^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)

// keyRe is the shape a key must have to be written. It is deliberately the same
// shape assignRe accepts when reading, so warden cannot write a line it would
// refuse to parse back.
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ErrInvalidKey means a key could not be written because its name is not a
// legal environment variable name.
var ErrInvalidKey = errors.New(
	"invalid key name: must match [A-Za-z_][A-Za-z0-9_]*")

// ValidateKey rejects a key that cannot be safely rendered into the file.
//
// A key is concatenated with "=" and the value to form a line, so a name
// carrying a newline would not produce one malformed assignment — it would
// produce two well-formed ones, the second of them entirely attacker-chosen.
// Because Get resolves a duplicated key to its last assignment, that injected
// line silently wins over the real one above it. Validating the name is what
// keeps a key from being a way to write a key.
func ValidateKey(key string) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("%q: %w", key, ErrInvalidKey)
	}
	return nil
}

// Parse reads path into a File.
func Parse(path string, opts Options) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	text := string(raw)
	if strings.Contains(text, "\n<<<<<<< ") || strings.HasPrefix(text, "<<<<<<< ") {
		return nil, ErrConflictMarkers
	}

	f := &File{path: path, mode: st.Mode().Perm(), opts: opts}
	f.crlf = strings.Contains(text, "\r\n")
	if f.crlf {
		text = strings.ReplaceAll(text, "\r\n", "\n")
	}
	f.finalNL = strings.HasSuffix(text, "\n")
	if f.finalNL {
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" && f.finalNL {
		return f, nil
	}

	for _, rawLine := range strings.Split(text, "\n") {
		l := line{raw: rawLine}
		if m := assignRe.FindStringSubmatch(rawLine); m != nil {
			hasExport := m[2] != ""
			if !hasExport || opts.AllowExport {
				l.key = m[3]
				l.export = hasExport
				l.value, l.quote = unquote(stripInlineComment(m[4]))
			}
		}
		f.lines = append(f.lines, l)
	}
	return f, nil
}

// stripInlineComment removes a trailing " # ..." from an unquoted value. A '#'
// inside quotes is part of the value and is left alone.
func stripInlineComment(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, `"`) || strings.HasPrefix(t, "'") {
		return t
	}
	if i := strings.Index(t, " #"); i >= 0 {
		return strings.TrimSpace(t[:i])
	}
	return t
}

// unquote strips a matching pair of surrounding quotes and, for double quotes,
// interprets the escape sequences inside.
//
// Single quotes are left literal, which is both POSIX behaviour and what dotenv
// loaders do: inside them a backslash is just a backslash. Double quotes carry
// escapes, so this is where \n becomes a newline — the same reading the app's
// own loader gives the file, which is the point. warden reporting a value the
// application does not see is a worse failure than either interpretation.
func unquote(s string) (string, byte) {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return unescapeValue(s[1 : len(s)-1]), '"'
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1], '\''
		}
	}
	return s, 0
}

// unescapeValue interprets the escapes legal inside double quotes.
//
// An unrecognised sequence is left exactly as written, backslash included.
// Swallowing it would silently rewrite a value nobody asked warden to touch,
// and warden changing a value it was only asked to read is the one outcome
// worth avoiding more than a missed escape.
func unescapeValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			// Not an escape warden knows: keep the backslash and let the next
			// iteration write the character after it.
			b.WriteByte(s[i])
			continue
		}
		i++
	}
	return b.String()
}

// Path returns the file's location.
func (f *File) Path() string { return f.path }

// Get returns the value for key.
func (f *File) Get(key string) (string, bool) {
	for i := len(f.lines) - 1; i >= 0; i-- { // last assignment wins, as the shell does
		if f.lines[i].key == key {
			return f.lines[i].value, true
		}
	}
	return "", false
}

// Keys returns every assigned key in file order, without duplicates.
func (f *File) Keys() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range f.lines {
		if l.key != "" && !seen[l.key] {
			seen[l.key] = true
			out = append(out, l.key)
		}
	}
	return out
}

// Set updates an existing key in place, or appends a new assignment.
// Set writes key = value, adding the assignment if the key is absent.
//
// The key is validated here rather than at each call site, so no write path can
// forget: this is the one funnel every value passes through on its way into the
// file, which makes it the only place the guarantee is cheap to keep.
func (f *File) Set(key, value string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	for i := range f.lines {
		if f.lines[i].key == key {
			f.lines[i].value = value
			f.lines[i].modified = true
			return nil
		}
	}
	f.lines = append(f.lines, line{key: key, value: value, modified: true})
	return nil
}

// Unset removes every assignment of key and reports how many it removed.
//
// Every one, not the last: Get resolves a duplicated key to its final
// assignment, so removing only that line would leave an earlier value live while
// reporting success. For a credential, that is the worst available outcome.
//
// Comments above a removed line are left in place. Whether a comment describes
// the key or the section it sits in is not knowable from the file, and guessing
// wrong deletes documentation the user wrote.
func (f *File) Unset(key string) int {
	kept := make([]line, 0, len(f.lines))
	removed := 0
	for _, l := range f.lines {
		if l.key == key {
			removed++
			continue
		}
		kept = append(kept, l)
	}
	f.lines = kept
	return removed
}

func render(l line) string {
	if !l.modified {
		return l.raw
	}
	prefix := ""
	if l.export {
		prefix = "export "
	}
	return prefix + l.key + "=" + quoteIfNeeded(l.value, l.quote)
}

// quoteIfNeeded renders a value for the file, choosing a quoting style that can
// actually carry it.
//
// A newline is the case that forces the choice. The parser is line-based, so a
// real line break would split the assignment and corrupt everything after it —
// the value is therefore escaped onto a single line, which is the convention
// dotenv loaders already read. Single quotes cannot carry escapes at all, so a
// value needing them is promoted to double quotes even when the line it replaces
// used single ones.
func quoteIfNeeded(v string, style byte) string {
	if strings.ContainsAny(v, "\n\r\\\"") {
		return `"` + escapeValue(v) + `"`
	}
	if style == '\'' && strings.Contains(v, "'") {
		return `"` + escapeValue(v) + `"`
	}
	if style != 0 {
		return string(style) + v + string(style)
	}
	if v == "" {
		return ""
	}
	if strings.ContainsAny(v, " \t#\"'$") {
		return `"` + escapeValue(v) + `"`
	}
	return v
}

// escapeValue is the inverse of unescapeValue, and the two must stay that way:
// before this pair existed, quoteIfNeeded escaped a quote that unquote never
// unescaped, so any value containing one came back with backslashes it did not
// go in with.
func escapeValue(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

// Save atomically rewrites the file, preserving its mode. It writes a temp file
// in the same directory and renames over the original, so an interrupted write
// cannot truncate a live .env.
func (f *File) Save() error {
	parts := make([]string, len(f.lines))
	for i, l := range f.lines {
		parts[i] = render(l)
	}
	out := strings.Join(parts, "\n")
	// With no lines left there is no shape to preserve, and a lone newline would
	// be content this file no longer has.
	if f.finalNL && len(f.lines) > 0 {
		out += "\n"
	}
	if f.crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}

	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, ".warden-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.WriteString(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, f.mode); err != nil {
		return err
	}
	return os.Rename(tmpName, f.path)
}
