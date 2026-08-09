package classify

import (
	"regexp"
	"strings"
)

// publicKeys are framework keys that are safe to read and set. Everything here
// is either non-sensitive by nature or already public by deployment.
var publicKeys = map[string]bool{
	"APP_NAME": true, "APP_ENV": true, "APP_DEBUG": true, "APP_URL": true,
	"APP_LOCALE": true, "APP_FALLBACK_LOCALE": true, "APP_TIMEZONE": true,
	"LOG_CHANNEL": true, "LOG_LEVEL": true, "LOG_STACK": true, "LOG_DEPRECATIONS_CHANNEL": true,
	"DB_CONNECTION": true, "DB_HOST": true, "DB_PORT": true, "DB_DATABASE": true,
	// DB_USERNAME is a deliberate call: not a credential on its own, frequently
	// needed, and fail-closed would otherwise hide it. Move it to the secret
	// patterns if that trade stops feeling right.
	"DB_USERNAME": true,
	"CACHE_STORE": true, "CACHE_PREFIX": true,
	"QUEUE_CONNECTION": true, "BROADCAST_CONNECTION": true,
	"SESSION_DRIVER": true, "SESSION_LIFETIME": true, "SESSION_DOMAIN": true,
	"FILESYSTEM_DISK": true,
	"MAIL_MAILER":     true, "MAIL_HOST": true, "MAIL_PORT": true, "MAIL_SCHEME": true,
	"MAIL_FROM_ADDRESS": true, "MAIL_FROM_NAME": true,
}

// secretContains matches anywhere in the key name.
var secretContains = []string{
	"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PRIVATE", "CREDENTIAL", "SALT", "SIGNATURE",
}

// secretSuffix matches the end of the key name.
var secretSuffix = []string{"_KEY", "_PWD", "_DSN", "_CERT"}

// secretExact matches the whole key name.
var secretExact = []string{"DATABASE_URL", "REDIS_URL"}

// shapePrefixes are credential formats recognisable from the value itself.
// Warden may inspect a value it will never emit, so this catches secrets whose
// key name gives nothing away.
var shapePrefixes = []struct{ prefix, rule string }{
	{"sk_live_", "shape:stripe-live"},
	{"sk_test_", "shape:stripe-test"},
	{"rk_live_", "shape:stripe-restricted"},
	{"github_pat_", "shape:github-pat"},
	{"ghp_", "shape:github-pat"},
	{"gho_", "shape:github-oauth"},
	{"ghs_", "shape:github-server"},
	{"xoxb-", "shape:slack-bot"},
	{"xoxp-", "shape:slack-user"},
	{"xapp-", "shape:slack-app"},
	{"AKIA", "shape:aws-access-key"},
	{"ASIA", "shape:aws-temp-key"},
	{"-----BEGIN", "shape:pem-block"},
	{"eyJ", "shape:jwt"},
}

// userinfoURL matches a URL carrying credentials in its authority component,
// e.g. https://admin:hunter2@host. Those are secrets no matter the key name.
var userinfoURL = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/@\s]+:[^/@\s]+@`)

// matchShape reports the rule name for a value that looks like a credential.
func matchShape(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	for _, s := range shapePrefixes {
		if strings.HasPrefix(value, s.prefix) {
			return s.rule, true
		}
	}
	if userinfoURL.MatchString(value) {
		return "shape:url-userinfo", true
	}
	return "", false
}

// matchName reports the rule name for a key whose name implies a secret.
func matchName(key string) (string, bool) {
	for _, s := range secretExact {
		if key == s {
			return "name:" + s, true
		}
	}
	for _, s := range secretSuffix {
		if strings.HasSuffix(key, s) {
			return "name:*" + s, true
		}
	}
	for _, s := range secretContains {
		if strings.Contains(key, s) {
			return "name:*" + s + "*", true
		}
	}
	return "", false
}
