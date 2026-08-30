package classify

import (
	"testing"

	"github.com/webteractive/warden/internal/secret"
)

func TestClassifyPrecedenceAndRules(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
		want  Class
	}{
		// Public allowlist.
		{"app name", "APP_NAME", "Warden", Public},
		{"app env", "APP_ENV", "local", Public},
		{"db host", "DB_HOST", "127.0.0.1", Public},
		{"db username", "DB_USERNAME", "root", Public},
		{"mail from name", "MAIL_FROM_NAME", "Warden", Public},
		{"vite prefix is always public", "VITE_ANYTHING_KEY", "abc", Public},

		// Name patterns.
		{"laravel app key", "APP_KEY", "base64:abc", Secret},
		{"suffix _KEY", "STRIPE_KEY", "abc", Secret},
		{"contains SECRET", "CLIENT_SECRET", "abc", Secret},
		{"contains TOKEN", "GH_TOKEN", "abc", Secret},
		{"contains PASSWORD", "DB_PASSWORD", "abc", Secret},
		{"contains PRIVATE", "PRIVATE_THING", "abc", Secret},
		{"suffix _DSN", "SENTRY_DSN", "abc", Secret},
		{"exact DATABASE_URL", "DATABASE_URL", "mysql://localhost/db", Secret},

		// Value shape beats the public allowlist.
		{"url with userinfo", "APP_URL", "https://admin:hunter2@staging.example.com", Secret},
		{"stripe live key in an innocent name", "MODE", "sk_live_abc123", Secret},
		{"github pat in an innocent name", "SETTING", "ghp_abc123", Secret},
		{"aws access key", "REGION_ID", "AKIAIOSFODNN7EXAMPLE", Secret},
		{"pem block", "CONFIG", "-----BEGIN RSA PRIVATE KEY-----", Secret},

		// A clean URL in an allowlisted key stays public.
		{"clean app url", "APP_URL", "https://warden.test", Public},

		// Fail closed.
		{"unknown key", "SOME_NEW_THING", "value", Secret},
		{"empty unknown key", "MYSTERY", "", Secret},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.key, secret.Secret(tc.value), nil, nil)
			if got.Class != tc.want {
				t.Errorf("Classify(%q) = %s (rule %q), want %s", tc.key, got.Class, got.Rule, tc.want)
			}
			if got.Rule == "" {
				t.Error("Result.Rule must always explain the decision")
			}
		})
	}
}

func TestClassStrings(t *testing.T) {
	if Public.String() != "public" || Secret.String() != "secret" {
		t.Errorf("Class strings wrong: %s / %s", Public, Secret)
	}
}

func TestResultNeverCarriesTheValue(t *testing.T) {
	r := Classify("STRIPE_KEY", secret.Secret("sk_live_canary"), nil, nil)
	if r.Rule == "sk_live_canary" || r.Class.String() == "sk_live_canary" {
		t.Error("Result must not embed the value")
	}
}
