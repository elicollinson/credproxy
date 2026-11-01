# credproxy

A local reverse proxy for macOS that adds API credentials to requests on their way out. The real keys stay in your login Keychain, in items that only the signed credproxy binary can read. Your services get a localhost URL and a caller token instead of a key. A compromised dependency in one of them can then use only the routes, methods and paths that service is allowed. It can't carry a key off and use it elsewhere.

```
service ──(caller token)──▶ 127.0.0.1:8787/openrouter/chat/completions
                              │ authenticate caller, check allowlist,
                              │ strip client credentials, inject the real key
                              ▼
                            https://openrouter.ai/api/v1/chat/completions
```

It is written in Go with only the standard library. `go.mod` has no dependencies. The Keychain is reached through cgo and Security.framework, never through `/usr/bin/security`. [DESIGN.md](DESIGN.md) has the threat model, every security rule (R1–R18) and the test plan.

## Requirements

- macOS, logged in to a GUI session (the login Keychain is only unlocked there)
- Go and the Xcode Command Line Tools (`xcode-select --install`), for cgo and `codesign`
- A code-signing identity on **this** Mac (next section)

## Setup

### 1. A signing identity, once

Every Keychain item trusts the binary's *designated requirement*, which comes from its signing identity. That's what lets a rebuilt binary keep reading the keys, so the identity has to stay the same. `make cert` prints the steps for a free self-signed one:

1. Keychain Access → Certificate Assistant → Create a Certificate…
2. Name `credproxy-signing`, Identity Type **Self Signed Root**, Certificate Type **Code Signing**. Tick "Let me override defaults" and set the validity to 3650 days. Save it in the login keychain.
3. Open the certificate, expand Trust, and set Code Signing to **Always Trust**.
4. Check: `security find-identity -v -p codesigning` lists it.

Export a `.p12` backup. A new certificate means running `key set` again for every key.

An "Apple Development" certificate from a free Apple ID also works: `make SIGN_IDENTITY="Apple Development: Your Name (TEAMID)"`. Pick one and stay with it.

When `codesign` asks to use the key, click **Allow**, not "Always Allow". Anything that can sign with this identity can read your keys (see [Limits](#what-this-does-not-protect-against)).

### 2. Build and write a config

```sh
make build                      # bin/credproxy, signed with the hardened runtime
mkdir -p ~/.config/credproxy
$EDITOR ~/.config/credproxy/config.json
chmod 600 ~/.config/credproxy/config.json
bin/credproxy config check
```

The config must be mode `0600` and owned by you, or credproxy won't start. Unknown fields and every invalid value are errors that name the field. The full schema is in [DESIGN.md §4](DESIGN.md#4-config-schema). A route looks like this:

```json
"openrouter": {
  "upstream": "https://openrouter.ai/api/v1",
  "credential": {"account": "openrouter"},
  "inject": {"type": "bearer"},
  "caller_auth": ["bearer"],
  "allow": [
    {"methods": ["POST"], "paths": ["/chat/completions"]},
    {"methods": ["GET"],  "paths": ["/models"]}
  ]
}
```

- `/<route>/<rest>` is forwarded to `<upstream><rest>`. The upstream comes only from the config.
- `allow` paths are exact, `*` matches one segment, and a trailing `/**` matches one or more.
- `caller_auth` lists where this route's callers put their token: `bearer`, `basic_password`, `header:<Name>` or `query:<name>`. Whatever the SDK uses for its API key goes here.
- `inject.type` is `bearer`, `header` (with `name`), `basic` (with `username`), `query` (with `name`) or `google_service_account` (with `scopes`).

### 3. Caller tokens

One per service:

```sh
bin/credproxy token new solenoid-node
```

It prints the token once, so give it to the service as its API key. Then paste the `token_sha256` line into `callers` in the config, with the routes that caller may use. Only the hash is stored.

### 4. Keys

```sh
bin/credproxy key set openrouter          # prompts with echo off
bin/credproxy key set gcp-sa < sa.json    # or pipe it in; then delete sa.json
bin/credproxy key list                    # account names only
bin/credproxy key check                   # can every configured credential be read?
bin/credproxy key rm openrouter
```

- `key set` refuses to run from an unsigned or ad-hoc build, because the item would be pinned to that one build.
- Secrets must be at least 16 bytes.
- A terminal line holds at most 1024 bytes, so pipe longer secrets in.
- `key set` replaces an existing item, which also resets its ACL to this binary.
- Changes take effect on the next request, with no restart, because credproxy reads the Keychain on every request.

### 5. Run it

```sh
make install     # ~/.local/bin/credproxy and a LaunchAgent; starts it now and at login
make uninstall
```

Logs go to `~/Library/Logs/credproxy.log`, one JSON line per request. A line holds the caller, route, method, path template, status, latency and byte counts. It never holds a URL, query, header or body.

The start line records the config's SHA-256, so an edit you didn't make shows up there. After editing the config, restart with `launchctl kickstart -k gui/$(id -u)/com.elicollinson.credproxy`.

## Per-service setup

In each case the service's base URL becomes `http://127.0.0.1:8787/<route>` and its API key becomes its caller token. From a Docker Desktop container, use `http://host.docker.internal:8787/<route>` and add `"host_aliases": ["host.docker.internal:8787"]` to the config.

| Service | `inject` | `caller_auth` | Client side |
|---|---|---|---|
| OpenRouter (OpenAI SDK) | `{"type": "bearer"}` | `["bearer"]` | `baseURL: "http://127.0.0.1:8787/openrouter"`, `apiKey: <token>` |
| GitHub (Octokit, fetch) | `{"type": "bearer"}` | `["bearer"]` | `baseUrl: "http://127.0.0.1:8787/github-issues"`, `auth: <token>` |
| Brave Search | `{"type": "header", "name": "X-Subscription-Token"}` | `["header:X-Subscription-Token"]` | requests to `…/brave/web/search` with `X-Subscription-Token: <token>` |
| Weights & Biases | `{"type": "basic", "username": "api"}` | `["basic_password"]` | `WANDB_BASE_URL=http://127.0.0.1:8787/wandb`, `WANDB_API_KEY=<token>` |
| Gemini API | `{"type": "query", "name": "key"}` | `["header:x-goog-api-key", "query:key"]` | SDK base URL `http://127.0.0.1:8787/gemini`, `apiKey: <token>`; set `"websocket": true` on the route for the Live API |
| Vertex AI (service account) | `{"type": "google_service_account", "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}` | `["bearer"]` | base URL `http://127.0.0.1:8787/gcp`, bearer `<token>` |

Notes:

- **Allowlist only what each service calls.** For GitHub that might be the issues of one repository, not all of `/repos/**`.
- **Gemini** sends the key as `?key=`. credproxy strips the caller's `key` and `x-goog-api-key` and adds the real key. This works on WebSocket upgrades too. After the upgrade, server frames are still searched for the key.
- **Service accounts.** credproxy signs a JWT with the SA key and exchanges it at `https://oauth2.googleapis.com/token`. An SA JSON naming any other `token_uri` is refused. The access token is cached until 5 minutes before it expires, and the SA JSON never leaves the proxy.

## Responses and errors

Refusals are JSON (`{"error": "<reason>"}`) with a fixed reason, never error text:

| Status | Reasons | Meaning |
|---|---|---|
| 400 | `bad_request_target`, `browser_origin`, `bad_host`, `non_canonical_path`, `bad_query`, `bad_body`, `conflicting_tokens`, `upgrade_not_allowed` | malformed, from a browser, or a path that isn't already canonical (no `..`, `%2e`, `%2f`, `//`, `;`) |
| 401 | `no_token`, `bad_token` | no caller token in the route's slots, or not a known one |
| 403 | `route_not_allowed`, `not_allowlisted` | caller may not use this route, or this method and path |
| 404 | `unknown_route` | |
| 413 | `body_too_large` | over `max_body_bytes` (32 MiB by default) |
| 429 | `rate_limited` | over the caller's `rate_limit_per_min` |
| 500 | `panic` | a bug; the log line has the reason and nothing else |
| 502 | `upstream_error`, `offsite_redirect`, `token_mint_failed` | upstream unreachable, redirect off the upstream, or Google's token endpoint failed |
| 503 | `keychain_locked`, `credential_missing`, `keychain_denied`, `credential_invalid`, `keychain_error` | see `key check` |

`keychain_denied` means the item's ACL doesn't trust this binary. That happens if it was created by something else, or if you changed signing identity. Run `key set` for it again. credproxy never shows a Keychain dialog while serving.

If an upstream echoes the key back, the caller gets `[redacted]***` of the same length, and the request is logged at warn level with `"alert": "upstream_echoed_secret"`.

## What this does not protect against

credproxy narrows what a compromised dependency can do. It is not a sandbox. Specifically:

- **Other services' tokens.** Your services all run as you, so code in one can read another's `.env` and use that caller's token. What you get between same-user processes is the union of every caller's allowlist. That still never includes a raw key, but it is not isolation. Per-caller tokens separate things that really are in different contexts, such as a container and the host.
- **Misuse within the allowlist.** A token allowed to create GitHub issues can create issues with your data in them. An LLM route will spend your credits. Keep allowlists and rate limits tight.
- **Config edits.** Same-user code can edit the config to widen an allowlist or add a route. credproxy refuses a config anyone else can read or write, and it logs the config's hash at start, but it can't stop you from editing your own file.
- **The signing key.** It sits in your login keychain. Anything that can sign with it can produce a binary the Keychain trusts, so never give `codesign` "Always Allow". For more protection, keep the identity in a separate keychain that stays locked except while you build.
- **Approving prompts.** If another program asks for a credproxy item and you click "Always Allow", it has the key from then on.
- **Root, a compromised macOS, or anything that can debug or replace the signed binary.** The hardened runtime blocks same-user debuggers and dylib injection, and nothing more.
- **Secrets in memory.** Go can't reliably wipe them. credproxy clears what it can and relies on nobody reading its memory.
- **Encodings it doesn't know.** The response scrubber looks for the raw key, its JSON-escaped form, its `basic` base64 form and its URL-encoded form. Any other encoding of an echoed key gets through. A key split across two fragments of one WebSocket message is missed too.
- **Running while you're away.** It runs only while you're logged in and the login Keychain is unlocked. Locked means `503 keychain_locked`, never a cached key.

## Development

```sh
make test                                   # gofmt, vet, go test -race
make test-keychain                          # T20 against a throwaway keychain; needs SIGN_IDENTITY
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

The adversarial tests run against fake TLS upstreams and an in-memory Keychain. A check over the whole suite fails the run if any fixture secret or token reaches the log or stderr. CI also runs govulncheck and zizmor, and checks that the binary links only system libraries.

## License

MIT
