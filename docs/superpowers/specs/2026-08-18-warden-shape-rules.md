# Warden — expanding the shape rules

**Date:** 2026-08-18
**Status:** proposed

## Problem

Rule 1 of the classifier — value shape, unwaivable — is the design's best idea. It works because
warden may read what it will never emit, so it can recognise a credential that every name-based
rule waves through. `APP_URL=https://admin:hunter2@staging.example.com` is the canonical case, and
it is caught.

The rule's coverage is a list, and the list in `internal/classify/rules.go` is fourteen prefixes
long: Stripe, GitHub, Slack, AWS, PEM, JWT. Everything else that ships a recognisable credential
format is missing — Anthropic, OpenAI, Google, GitLab, npm, SendGrid, Shopify, DigitalOcean,
Supabase, HuggingFace, Figma, Stripe webhook signing secrets. Each absence is a fail-open on the
one rule that cannot be waived, and each one bites in the same place: a public-allowlisted or
innocuously-named key holding a live credential.

`AI_ENDPOINT=sk-ant-api03-…` classifies public today if a schema says so, and `warden get` prints
it.

The list also misses two *shapes* rather than vendors: a URL carrying a single-component
credential userinfo (every Sentry DSN), and the general case of a long random string with no
vendor marker at all — which is what most self-issued secrets look like.

## Design

### More prefixes

Added to `shapePrefixes`, each with a rule name so `classify` stays diagnosable:

| Prefix | Rule |
|---|---|
| `sk-ant-` | `shape:anthropic` |
| `sk-proj-`, `sk-svcacct-` | `shape:openai` |
| `AIza`, `ya29.` | `shape:google-api-key`, `shape:google-oauth` |
| `glpat-`, `gldt-`, `glrt-` | `shape:gitlab-token` |
| `npm_` | `shape:npm-token` |
| `whsec_` | `shape:stripe-webhook` |
| `SG.` | `shape:sendgrid` |
| `shpat_`, `shpss_`, `shpca_` | `shape:shopify` |
| `dop_v1_`, `doo_v1_`, `dor_v1_` | `shape:digitalocean` |
| `sbp_`, `sb_secret_` | `shape:supabase` |
| `hf_` | `shape:huggingface` |
| `figd_`, `figu_` | `shape:figma` |
| `xoxa-`, `xoxr-`, `xoxe.` | `shape:slack-legacy` |
| `AGE-SECRET-KEY-1` | `shape:age-identity` |
| `nsec1` | `shape:nostr-privkey` |
| `pypi-AgEI` | `shape:pypi-token` |
| `atlassian`/`ATATT3` | `shape:atlassian-token` |

Bare `sk-` (legacy OpenAI) is included despite being broad. It is a two-character prefix that will
occasionally catch something innocent, and the cost of that is precisely one `.env.schema`
override — while the cost of missing it is a printed API key. Fail closed is the house rule.

Deliberately **not** added: `pk_live_`, `pk_test_`, `AC…` Twilio account SIDs, `ssh-rsa` public
keys. These are publishable identifiers, and adding them would make the shape rules a
classification in both directions.

### A public shape rule, considered and rejected

`pk_live_` is *provably* safe to print. A rule that marked it public would be correct and would
save a schema override.

It is rejected because the shape rules are unwaivable. An unwaivable rule that makes a value
*readable* inverts the property that makes rule 1 trustworthy — today, shape can only ever tighten,
and that one-directionality is why it can safely outrank a human-authored schema. A shape rule that
loosens would mean a value's own content could unmask it, and a mistake in that table prints a
credential with no override available to stop it. The asymmetry stays.

### Single-component URL userinfo

`userinfoURL` requires `user:pass@`. A Sentry DSN has no colon:

```
SENTRY_DSN=https://a3f91c2b8e44d6f7a1b2c3d4e5f60718@o12345.ingest.sentry.io/456
```

New rule `shape:url-token-userinfo`: a URL whose userinfo has no colon, is at least 16 characters,
and is confined to a token alphabet. This deliberately does not fire on `https://git@github.com/…`
or `https://user@host/` — a short human-looking username is not a credential. `*_DSN` already
catches the Sentry case by name; this catches it under `MONITORING_URL`, `REPORT_ENDPOINT`, and
every other name nobody thought of.

### High-entropy fallback, and where it sits

The general case: 40 characters of base64 with no vendor marker. The rule:

- length ≥ 32;
- the whole value matches `^[A-Za-z0-9+/=_\-]+$`;
- it contains at least one digit **and** one letter;
- and either mixed case, or length ≥ 40.

Note what this is not: **Shannon entropy.** Entropy over a short string is noisy, and uniform hex
tops out at exactly 4.0 bits per character — so any threshold high enough to exclude English prose
also excludes a 64-character hex API key, which is the single most common secret format there is.
A charset-and-length rule is cruder, entirely predictable, and explains itself in a sentence,
which matters for a rule people will argue with.

Exclusions, to keep the false-positive rate survivable: anything containing whitespace, `.`
segments that parse as a hostname, a leading `/` (paths), an `@` (emails), or a match for semver or
an ISO date.

**This rule is waivable, and it is the only shape rule that is.** It sits at position 2½ in the
precedence order — after the `.env.schema` override, before the public allowlist:

1. Recognised credential formats — unwaivable
2. `.env.schema` override
3. **High-entropy fallback** — new
4. Public allowlist
5. Secret name patterns
6. Default: secret

That placement is the whole design. A heuristic this fuzzy *must* be correctable by a human, so
the schema outranks it. But it must outrank the public allowlist, because its entire purpose is to
catch a random blob sitting in an allowlisted key — `CACHE_PREFIX=aG9sZG9uYXNlY29uZA…` should not
be printable. Reported as `shape:high-entropy` so a surprising result is diagnosable in the one
place people will need it.

Because it is waivable, `classify --set public` works on it — and `write.Reclassify`'s
`ErrUnwaivableShape` check must consult only the *unwaivable* rule set, or a high-entropy false
positive becomes uncorrectable. That is a real bug this spec would otherwise introduce, and
`classify.ShapeRule` splits into `ShapeRule` (unwaivable, used by `Reclassify`) and
`WeakShapeRule` (the entropy fallback, used only by `Classify`).

## Command surface

Unchanged. `warden classify <KEY>` reports the new rule names.

One addition: `warden classify --why <KEY>` listing every rule that *would* have matched, not just
the winner. When a key classifies secret for three reasons, knowing that an override fixes only
one of them saves an argument with the tool.

## Invariants

Upheld, with one sharpened:

- Invariant 4 (an unmatched key classifies as secret) is what justifies every judgement call
  above: a false positive costs one schema line, a false negative prints a credential.
- **Shape rules only ever tighten.** No shape rule may cause a value to be revealed. Stated here
  because the `pk_live_` idea will come back.

## Testing

- The classification table grows one row per prefix, using values shaped like the real thing and
  containing no real credential.
- **A false-positive corpus** is the important half, and it does not exist yet: legitimate public
  values that must survive the new rules — long filesystem paths, base64-encoded PNG data URIs,
  UUIDs, ISO timestamps, semver strings, `postgres://localhost:5432/app`, a 60-character
  `MAIL_FROM_NAME`, a `VITE_BUILD_HASH`. Every one asserted to keep its pre-change class.
- Precedence tests for the new position: a high-entropy value in an allowlisted key classifies
  secret; the same key with a `.env.schema` `public` entry classifies public; a `sk-ant-` value
  with the same override stays secret.
- `Reclassify` on a high-entropy false positive succeeds; on an `sk-ant-` value it still fails with
  `ErrUnwaivableShape`. This pair is the test that keeps the split between `ShapeRule` and
  `WeakShapeRule` honest.
- `classify --why` listing multiple matches, and a canary entry for it.

## Out of scope

- Verifying a credential against its provider to decide the class. Network access in a classifier
  is a much larger idea; see the note at the end of the rotation-age spec.
- Structural parsing of values (decoding a JWT to read `exp`, validating an AWS key's checksum).
  Prefix matching is the right depth for a rule that must never be wrong in the loosening
  direction.
- Pulling the prefix list from a shared upstream feed at runtime. A classifier whose behaviour
  changes without a release is not testable.
