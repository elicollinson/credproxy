# credproxy design

Status: Phase 0, for review. Nothing here is built yet.

## 1. Threat model

**What we defend against.** A malicious or compromised npm package running inside one of my Bun services (Solenoid-Assistant, solenoid-node, solenoid-security). That code runs as my user. It can read `process.env`, every file my user can read, and open any network connection. Today that is enough to take every API key the service uses and spend them from anywhere, for as long as the keys stay valid.

**What credproxy changes.** The services hold only a localhost base URL and a caller token. The real keys live in the login Keychain, in items that only the signed credproxy binary can read without a prompt. A compromised service can then:

- use only the routes, methods and paths its token allows,
- only while credproxy is running on my machine,
- with every request logged.

It never holds a key it could carry off and use elsewhere. Revoking a caller is a config edit and a restart. The upstream key never changes.

**What it does not change (said plainly, because the brief overstates one point).** All my services run as the same user, so a compromised dependency in service A can read service B's `.env` and use B's token too. Per-caller tokens separate services that sit in different security contexts, such as a Docker container versus the host, or different users. Between same-user processes they give attribution and blast-radius limits for honest mistakes, not isolation. In that case the protection is the union of every caller's allowlist, which still never includes the raw keys. That is the property worth having. I'll say this in the README rather than imply more.

**Out of scope**, as briefed: root; anyone who can debug, patch or replace the signed binary; a compromised macOS; multi-user use; a UI; general-purpose gateway features; AWS SigV4.

**Residual risks we accept:**

- **Keychain prompts.** Another process asking for a credproxy item gets a Keychain dialog that names it. If I click "Always Allow", that process is trusted from then on. Synthetic clicks on that dialog are blocked by TCC, so the defence holds as long as I don't approve the dialog myself.
- **The signing key.** The Keychain trusts whatever is signed with my identity, and that identity's private key is in my login keychain too. Same-user code that can use the key can sign its own binary as credproxy and read every item. When `codesign` asks to use the key, I click "Allow", never "Always Allow", so every signing prompts and an unexpected prompt is the signal. Stronger: keep the identity in a separate keychain that stays locked except during `make build`.
- **Port squatting.** Same-user code can stop the LaunchAgent and bind its port to collect caller tokens. Caller tokens aren't upstream keys, so this gains it nothing beyond what it already had.
- **Config edits.** Same-user code can edit the config to widen its own allowlist. The config file is user-writable by necessity. **Mitigation:** credproxy refuses to start unless the config file is mode `0600` or stricter and owned by me, and it logs a SHA-256 of the config at start. It doesn't stop the edit, but the change shows up in the log. I don't think anything stronger is worth its complexity under this threat model. Push back if you disagree.

## 2. Pushback on the brief

1. **"A single static binary".** On macOS a fully static binary isn't possible. Everything links `libSystem` dynamically, and cgo links `Security.framework` and `CoreFoundation.framework` dynamically. What we can promise is one self-contained executable that links only Apple system frameworks, with no third-party dylibs. `otool -L` will be checked in CI.
2. **LaunchAgent, not LaunchDaemon.** The login Keychain is only reachable from my user session. The plist installs into `~/Library/LaunchAgents` and runs in the `gui/<uid>` domain, so credproxy runs only while I'm logged in. That fits "only while it's running".
3. **The Docker bridge listener is probably unnecessary on Docker Desktop for Mac.** The bridge lives inside Docker's Linux VM, so there's no host interface to bind to. Containers reach host services via `host.docker.internal`, which Docker Desktop forwards to the host's loopback. I'll keep the optional extra listener (it's about three lines), but the README will tell container users to point at `http://host.docker.internal:8787` against the default `127.0.0.1` listener. I'll verify this in Phase 1.
4. **"Accept the caller token in whatever slot the SDK uses" is too loose.** If any slot is accepted on any route, the order and precedence rules get fuzzy, and a fuzzy credential rule is exactly where proxies get bypassed. Instead, each route declares an explicit ordered list of `caller_auth` slots (§4.3, default `["bearer"]`). The request must carry the token in exactly one of them; two different tokens is a 400.
5. **Clean, then match → reject instead of cleaning.** If `path.Clean` changes the path, the request was not canonical. Matching the cleaned path and forwarding the original bytes is the classic split, so we reject the request rather than guess. We match on the canonical path and forward exactly those bytes (§5, R5).
6. **Response scrubbing must replace with the same length.** Replacing a secret with the literal `[redacted]` changes the body length. That breaks `Content-Length` responses and WebSocket frame lengths. So we replace with `[redacted]` padded with `*` to the secret's length (secrets are ≥16 bytes; enforced at `key set`).

    We also strip the client's `Accept-Encoding`, so Go's transport negotiates gzip itself and decompresses transparently. Otherwise every scrub of a compressed body is a no-op. WebSocket compression (`permessage-deflate`) is stripped from the upgrade for the same reason. This is defensive, with a known gap: the scrub looks for the raw secret, its `basic` base64 form and its JSON-escaped form. Any other encoding gets through.
7. **Same-host redirects.** These aren't passed through as-is. A `Location` on the configured upstream host under the route's base path is rewritten to the matching `/<route>/…` proxy path. That way the caller re-enters credproxy and the allowlist applies again. Any other `Location` is a 502 with a logged reason, as briefed. Passing the raw upstream URL back would make SDKs that follow redirects hit the upstream directly with no credential, so they fail confusingly.
8. **Timeouts: no total-response deadline.** This matches the decision in solenoid-node: no wall-clock deadlines on LLM work, because that time varies with compute speed. Instead:
    - dial (10 s) and TLS handshake (10 s) timeouts,
    - a server `ReadHeaderTimeout` (10 s, against slowloris),
    - body size limits,
    - `ResponseHeaderTimeout` off by default, with an optional per-route `first_byte_timeout_ms`.

    Stall detection stays in the callers, which already have a provider stall guard. A mid-stream idle timeout in the proxy would duplicate it.
9. **Zeroing secrets is mostly not achievable in Go, and I won't pretend it is.** Once a secret becomes a header value it's an immutable `string` on the GC heap, and `net/http` copies it further. We zero the `[]byte` returned from cgo after converting it, and the SA JSON and parsed RSA key after each mint (best effort, `big.Int` internals included). Beyond that, protection comes from the out-of-scope rule that nothing may read credproxy's memory. The hardened runtime enforces this against same-user debuggers and `DYLD_INSERT_LIBRARIES` (R18).
10. **Line budget.** My estimate is about 1,100 lines without tests:

    | Part | Lines |
    |---|---|
    | config + validation | 180 |
    | auth + allowlist | 130 |
    | proxy core, redirect handling, scrub | 260 |
    | injectors, Google SA included | 200 |
    | Keychain cgo | 150 |
    | CLI + termios | 130 |
    | logging | 50 |

    What drives it is Google SA (JWT mint, token exchange, single-flight cache) and the cgo layer. It's over budget by roughly the size of SA support, so if it needs trimming, that's the candidate.
11. **`govulncheck` and zizmor are CI tools, not module dependencies.** They are installed in CI at pinned versions. `go.mod` stays free of `require` lines.

## 3. Keychain approach

### Choice: file-based login Keychain with an ACL that trusts only this binary

`key set` calls `SecItemAdd` with these attributes:

- `kSecClass = kSecClassGenericPassword`
- `kSecAttrService = <service>` (default `credproxy`)
- `kSecAttrAccount = <account>`
- `kSecValueData = <secret>`
- `kSecAttrAccess = access`

`access` comes from `SecAccessCreate(label, [self])`, where `self` is from `SecTrustedApplicationCreateFromPath(NULL, &self)`. A `NULL` path means "the calling application". `key set` is a subcommand of the same signed binary, so the creator is the daemon's identity.

Reads use `SecItemCopyMatching` with `kSecReturnData`. For a signed binary, the ACL stores the code's **designated requirement** (DR), not its cdhash, so access survives rebuilds as long as the DR stays the same. With ad-hoc signing the ACL pins the cdhash and every rebuild prompts, which is why constraint 5 (a stable identity) matters.

**Signing identity: a self-signed code-signing certificate, no developer account needed.** It is created once, in Keychain Access (Certificate Assistant → Create a Certificate, type "Code Signing") or with `openssl`, and set to Always Trust for code signing. Its DR is:

```
identifier "com.elicollinson.credproxy" and certificate leaf = H"<sha1 of the certificate>"
```

That DR is identical across builds and install paths. A free Apple ID "Apple Development" certificate from Xcode works too. Its DR is `identifier … and anchor apple generic and certificate leaf[subject.CN] = "Apple Development: …" and …`. The paid program only matters for distributing to other people, which is out of scope. The Makefile takes either identity as `SIGN_IDENTITY`. `make cert` prints the steps for the self-signed one.

Trade-offs between the two:

- **Self-signed pins the exact certificate.** If it is ever regenerated or lost, the DR changes and every item must be re-created with `key set`. It can be issued for 10 years, and losing it costs a few minutes, not a key rotation.
- **Apple Development certificates expire after a year,** but their DR names the CN rather than the leaf, so a renewal keeps access.
- **Partition list (to verify in Phase 3).** Since macOS 10.12, items also carry a partition list. A team-signed binary gets `teamid:<TEAMID>`, but a self-signed certificate has no team ID. If securityd falls back to a per-cdhash partition there, every rebuild would raise one "allow" prompt despite the stable DR. T20 includes "rebuild, re-sign, read without a prompt" to settle this. If it fails, the fallback is the free Apple Development certificate, which has a team ID, with no design change.

`/usr/bin/security` is in neither the ACL nor the partition list, which is the point of constraint 2.

**Deprecation status.** These APIs have been marked deprecated since 10.10 ("SecKeychain is deprecated"), but they are still declared in the macOS 26.5 SDK on this machine. They are the only supported way to put a per-application ACL on a file-based Keychain item. We compile the cgo file with `-Wno-deprecated-declarations` and isolate it behind an interface (§3.3), so replacing it later touches one file.

### Rejected alternative: the data protection keychain

This is the "modern equivalent": `kSecUseDataProtectionKeychain = true`, with access controlled by `keychain-access-groups`. On macOS, that entitlement is restricted and needs a provisioning profile. A provisioning profile can only be embedded in a bundle, so credproxy would have to ship as `credproxy.app/Contents/MacOS/credproxy` with an App ID registered in the developer portal. Access groups are also keyed by team ID, so any of my other team-signed apps could read the items.

That's more moving parts and coarser access than the per-binary ACL. **Revisit it if Apple actually removes `SecAccessCreate`.**

### Read policy: per request, no cache

`SecItemCopyMatching` is a securityd IPC call of about 1–3 ms, which is noise next to an upstream API call. Reading per request means:

- no cache to invalidate,
- `key set` and `key rm` take effect on the next request,
- a locked Keychain (after sleep, with "lock on sleep" set) is reported as a clear 503 `keychain_locked` rather than served from stale memory,
- secrets spend the least time in our heap.

The one exception is `google_service_account`: the minted access token (not the SA JSON) is cached until 5 minutes before expiry. The SA JSON is read from the Keychain only when we mint.

### Interface

```go
type SecretStore interface {
    Get(service, account string) ([]byte, error) // ErrNotFound, ErrLocked, ErrDenied
}
```

Production uses the cgo Keychain. Tests use an in-memory fake. `key list` enumerates the accounts under the service via `kSecMatchLimitAll` with `kSecReturnAttributes` only, never data. `key check` calls `Get` for each configured credential and reports ok or the error code, never the length or the value.

**References:**

- TN3137 *On Mac keychain APIs and implementations*: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
- `SecAccessCreate`: https://developer.apple.com/documentation/security/1393522-secaccesscreate
- `SecTrustedApplicationCreateFromPath`: https://developer.apple.com/documentation/security/1393375-sectrustedapplicationcreatefromp
- `kSecAttrAccess`: https://developer.apple.com/documentation/security/ksecattraccess
- `kSecUseDataProtectionKeychain`: https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
- Code-signing requirement language (designated requirements): https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html

## 4. Config schema

The config is JSON, decoded with `DisallowUnknownFields` plus a check for trailing data. Every field below is validated, and any error stops startup with the field path in the message. The default path is `~/.config/credproxy/config.json`, overridable with `-config`.

```json
{
  "listen": ["127.0.0.1:8787"],
  "host_aliases": ["host.docker.internal:8787"],
  "allow_non_loopback": false,
  "max_body_bytes": 33554432,
  "routes": {
    "openrouter": {
      "upstream": "https://openrouter.ai/api/v1",
      "credential": { "service": "credproxy", "account": "openrouter" },
      "inject": { "type": "bearer" },
      "caller_auth": ["bearer"],
      "allow": [
        { "methods": ["POST"], "paths": ["/chat/completions", "/embeddings"] },
        { "methods": ["GET"],  "paths": ["/models"] }
      ]
    },
    "brave": {
      "upstream": "https://api.search.brave.com/res/v1",
      "credential": { "account": "brave" },
      "inject": { "type": "header", "name": "X-Subscription-Token" },
      "caller_auth": ["header:X-Subscription-Token"],
      "allow": [{ "methods": ["GET"], "paths": ["/web/search"] }]
    },
    "wandb": {
      "upstream": "https://api.wandb.ai",
      "credential": { "account": "wandb" },
      "inject": { "type": "basic", "username": "api" },
      "caller_auth": ["basic_password"],
      "allow": [{ "methods": ["POST"], "paths": ["/graphql", "/files/**"] }]
    },
    "gemini": {
      "upstream": "https://generativelanguage.googleapis.com",
      "credential": { "account": "gemini" },
      "inject": { "type": "query", "name": "key" },
      "caller_auth": ["header:x-goog-api-key", "query:key"],
      "websocket": true,
      "allow": [
        { "methods": ["POST"], "paths": ["/v1beta/models/*"] },
        { "methods": ["GET"],  "paths": ["/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent"] }
      ]
    },
    "github-issues": {
      "upstream": "https://api.github.com",
      "credential": { "account": "github-issues" },
      "inject": { "type": "bearer" },
      "caller_auth": ["bearer"],
      "allow": [{
        "methods": ["GET", "POST", "PATCH"],
        "paths": ["/repos/elicollinson/Solenoid-Assistant/issues",
                  "/repos/elicollinson/Solenoid-Assistant/issues/*",
                  "/repos/elicollinson/Solenoid-Assistant/issues/*/comments"]
      }]
    },
    "gcp": {
      "upstream": "https://us-central1-aiplatform.googleapis.com",
      "credential": { "account": "gcp-sa" },
      "inject": { "type": "google_service_account",
                  "scopes": ["https://www.googleapis.com/auth/cloud-platform"] },
      "caller_auth": ["bearer"],
      "allow": [{ "methods": ["POST"], "paths": ["/v1/projects/my-proj/locations/us-central1/**"] }]
    }
  },
  "callers": {
    "solenoid-assistant": {
      "token_sha256": "<64 hex>",
      "routes": ["openrouter", "gemini", "github-issues", "gcp"],
      "rate_limit_per_min": 120
    },
    "solenoid-node": {
      "token_sha256": "<64 hex>",
      "routes": ["openrouter", "brave", "wandb"]
    }
  }
}
```

### 4.1 Validation rules

- **`listen`:** each entry is `host:port` with a literal IP. A non-loopback IP requires `"allow_non_loopback": true` and logs a warning at every start. `0.0.0.0` and `::` are non-loopback.
- **`host_aliases`** are extra `Host` values to accept (R7), each `host:port`. Containers reaching the proxy through `host.docker.internal` need one.
- **Route names** match `^[a-z0-9][a-z0-9-]{0,62}$`, so they are always a single safe path segment.
- **`upstream`** must:
  - use `https`,
  - have no userinfo, query or fragment,
  - have a host that is a DNS name, not an IP literal (TLS verification by name),
  - have a canonical path (`Clean(p) == p`, no trailing `/`).
- **`credential.service`** defaults to `credproxy`. **`credential.account`** is required.
- **`inject.type`** is one of `bearer`, `header`, `basic`, `query` or `google_service_account`, and each type's own fields are required and checked:
  - `header` names must be valid tokens, and not hop-by-hop, `Host` or `Content-Length`.
  - `scopes` must be non-empty `https://www.googleapis.com/auth/` URLs.
- **`caller_auth`** entries are `bearer`, `basic_password`, `header:<Name>` or `query:<name>`. If a header slot is listed, it must not be `Cookie`.
- **`websocket`** defaults to false. When false, an upgrade request is a 400.
- **`allow`** needs at least one rule. Methods are uppercase and drawn from GET, HEAD, POST, PUT, PATCH and DELETE. Paths are canonical, start with `/`, and may contain only:
  - `*`: exactly one non-empty segment,
  - a trailing `/**`: one or more segments.

  Glob characters may appear only as whole segments.
- **`callers`:**
  - `token_sha256` is 64 lowercase hex characters, unique across callers,
  - `routes` is non-empty and names existing routes,
  - `rate_limit_per_min` defaults to 60 and must be between 1 and 10,000. Burst equals the per-minute value ÷ 6, with a minimum of 1.
- **`max_body_bytes`** defaults to 32 MiB and can be overridden per route.
- **Unused routes:** a route that no caller references is a warning, not an error.

### 4.2 Request mapping

`/<route>/<rest>?<query>` → `<upstream><rest>?<query minus stripped params, plus injected param>`.

### 4.3 Caller-auth slots

| slot | where the token is read | used by |
|---|---|---|
| `bearer` | `Authorization: Bearer <t>` or `Authorization: token <t>` | OpenAI SDK, Octokit, fetch |
| `basic_password` | the password half of `Authorization: Basic` (username ignored) | wandb |
| `header:<N>` | header `N` | Brave, Gemini SDK |
| `query:<n>` | query parameter `n` | Gemini WebSocket, older SDKs |

## 5. Security invariants

Each rule gets at least one test (§7).

- **R1. Upstream comes only from config.** The outbound scheme, host and port come only from the route's `upstream`. The `Host` header, absolute-form request URIs, `X-Forwarded-*` and `Forwarded` never influence it. Absolute-form requests (`GET https://…`) and `CONNECT` are rejected with 400.
- **R2. No credential before authorization.** Nothing is read from the Keychain and nothing is sent upstream until:
  1. the caller is authenticated,
  2. the route is in the caller's list,
  3. the method and path match the route's allowlist,
  4. the rate limit admits the request.

  Failures are: 401 (no or invalid token), 403 (route, method or path not allowed), 429 (rate limited), 400 (malformed).
- **R3. Constant-time caller lookup.** `sha256(token)` is compared against every configured hash with `subtle.ConstantTimeCompare`, with no early exit. An unknown token and a known token take the same path.
- **R4. Exactly one token slot.** The token is read only from the route's declared `caller_auth` slots. Different values in two slots is a 400.
- **R5. Canonical paths only.** These are rejected with 400 before routing:
  - percent-encodings of `.`, `/`, `\` and NUL (`%2e`, `%2f`, `%5c`, `%00`, in any case),
  - a literal `\` or `;`,
  - empty segments (`//`),
  - `.` or `..` segments,
  - a trailing `.` segment,
  - any path where `path.Clean(p) != p`, which includes a trailing slash.

  The forwarded path is byte-for-byte the matched path.
- **R6. Strip, then inject.** Before injection the proxy removes:
  - `Authorization`, `Proxy-Authorization`, `Cookie`,
  - every header named in the route's `caller_auth` or `inject`, plus `X-Api-Key`, `Api-Key` and `X-Goog-Api-Key`,
  - every query parameter named in `caller_auth` or `inject`, in every case variant.

  The injected credential is the only one upstream sees. `Set-Cookie` is stripped from responses.
- **R7. Header hygiene.** The proxy:
  - removes hop-by-hop headers and anything named in `Connection`,
  - removes `X-Forwarded-*`, `Forwarded`, `Via` and `X-Real-Ip`,
  - never adds `X-Forwarded-For`,
  - never emits CORS headers.

  It rejects requests with an `Origin` header (no browser callers), and requests whose `Host` isn't one of its listen addresses, `localhost:<port>` or a configured `host_aliases` entry. That blocks DNS rebinding from a browser tab.
- **R8. No redirects followed.** The transport never follows redirects (`ReverseProxy` doesn't, and we assert it).
  - A 3xx with a `Location` on the same scheme, host and port, under the upstream base path, is rewritten to the proxy path.
  - Any other `Location` gets a 502, and the reason is logged without the URL.
- **R9. TLS.** Verification is always on, with `MinVersion` set to TLS 1.2. There is no `InsecureSkipVerify` anywhere in non-test code (grep check in CI). HTTP/2 stays enabled (`ForceAttemptHTTP2`).
- **R10. No secrets in output.** Each log line is one JSON object with exactly these fields: `time`, `caller`, `route`, `method`, `path_template` (the allowlist pattern that matched, never the real path), `status`, `latency_ms`, `bytes_in`, `bytes_out`, plus `reason` (a fixed enum string) on failure and `alert` when R11 fired. Specifically:
  - No URL, query, header or body is ever logged.
  - `ReverseProxy.ErrorHandler` and `ErrorLog` are replaced, and so is `http.Server.ErrorLog`. Error text is never logged, so what an error message happens to contain (a host, a URL from some future wrapper) can't matter.
  - Handler panics are recovered by our own middleware, which logs `reason: "panic"` with no value or stack. `http.ErrAbortHandler` is re-panicked so streaming aborts behave as normal.
  - Error responses to callers are fixed strings.
- **R11. Response scrubbing.** Response headers and body are scanned for the injected secret (raw, plus its basic-auth base64 and its JSON-escaped forms) and replaced at the same length. A match logs `alert: "upstream_echoed_secret"` at warn level. The streaming matcher keeps a tail of `len(secret)−1` bytes across chunks, and each chunk is flushed immediately after the scan.
- **R12. Streaming.** `FlushInterval: -1`. There is no total-response timeout and no `WriteTimeout`. SSE events reach the caller as they arrive.
- **R13. WebSocket.** Upgrades are allowed only on routes with `"websocket": true`. They go through the same auth, allowlist, strip and inject (including `query` injection). `Sec-WebSocket-Extensions` is stripped. After the 101, server-to-client frames are redacted one frame at a time and released as soon as each is complete. (The byte-stream scrubber's held-back tail could stall the last message of a turn.) Server frames that are masked, or larger than 16 MiB, close the connection. A secret split across two fragments of one message is not caught.
- **R14. Size limits.** A declared `Content-Length` over the limit is a 413 straight away. A body of unknown length is read into memory first, up to the limit, so an oversized one never reaches the upstream. Headers are limited by `MaxHeaderBytes` (64 KiB).
- **R15. Isolated rate limits.** Each caller has its own token bucket, and one caller's exhaustion never affects another's. A 429 never reveals other callers' state, and it is decided only after authentication, so it reveals nothing to an unauthenticated client.
- **R16. Google SA.** The SA private key is used only inside the process to sign the JWT. Rules:
  - `token_uri` must equal `https://oauth2.googleapis.com/token`; anything else refuses to mint.
  - The access token is cached until 5 minutes before `expires_in`, with single-flight refresh.
  - A refresh failure is a 502 and is never retried in a loop.
  - An SA JSON that doesn't parse, has no RSA key, or names another `token_uri` is a 503 `credential_invalid`, and nothing is contacted.
- **R17. Startup fails closed.** Any config error, a config file looser than `0600` or not owned by me, or a non-loopback listener without opt-in stops startup.
- **R18. Signed and hardened.** The `make` build signs with `$(SIGN_IDENTITY)` (self-signed or Apple Development, §3), using `--options runtime` (the hardened runtime) and no `get-task-allow` entitlement. That blocks same-user debugger attach and dylib injection. `key set` refuses to run unless the running binary is validly signed (`SecCodeCheckValidity` on self). Without that check, an unsigned dev build would create items pinned to a throwaway cdhash.

## 6. Components (planned layout)

```
cmd/credproxy/main.go     subcommands: serve, token new, key set|rm|list|check, config check
internal/config/          schema, strict decode, validation
internal/proxy/           handler, auth, allowlist, rewrite, redirects, scrub, ratelimit, log
internal/inject/          Injector interface + bearer, header, basic, query, gsa
internal/keychain/        SecretStore; keychain_darwin.go (cgo), fake for tests
internal/term/            termios no-echo read (TIOCGETA/TIOCSETA via syscall.Syscall(SYS_IOCTL))
packaging/                com.elicollinson.credproxy.plist.tmpl
Makefile                  build, sign, test, install, uninstall
```

The `Injector` interface:

```go
type Injector interface {
    // Acquire runs after R2, before forwarding, so it can fail: a missing
    // key, a locked Keychain, a token endpoint that's down. A type that
    // mints tokens (google_service_account) keeps its cache behind it.
    Acquire(ctx context.Context, store keychain.Store) (Cred, error)
}

// Cred is attached in ReverseProxy's Rewrite, which can't fail.
type Cred struct {
    Header, Param, Value string
    Needles []string // forms of the secret for the R11 scrubber
}
```

Which headers and query parameters each route strips (R6) is computed once, in config validation, from `caller_auth` and `inject`.

Adding a type later means one file plus one case in config validation.

**Caller tokens.** `credproxy token new <caller>` prints `cpx_<43 base64url chars>` (32 random bytes from `crypto/rand`) once to stdout. It then prints the `token_sha256` line to paste into the config. Nothing is stored.

## 7. Test plan

All tests run against `httptest.NewTLSServer` fake upstreams, with the fake `SecretStore` and the test server's CA injected into the transport. The real transport configuration is used otherwise. A global log sink captures every byte from our logger, `ErrorLog`s, and stderr during the suite. `TestMain` then asserts that none of the fixture secrets, caller tokens, or `key=` values appear in it (R10).

Adversarial tests are written first. Each must fail before its code exists, and fail-first is checked by committing the tests before the implementation in Phase 1.

| # | Test | Rules |
|---|---|---|
| T1 | Caller requests a route not in its list → 403; upstream hit counter is 0; store `Get` counter is 0 | R2 |
| T2 | No token, wrong token, token in an undeclared slot → 401, upstream 0, store 0 | R2, R4 |
| T3 | Same token, two slots, different values → 400 | R4 |
| T4 | Timing smoke test: unknown vs known-prefix tokens go through the same code path (assert every hash is compared via a counting comparator) | R3 |
| T5 | Traversal table: `…/issues/../../../user`, `%2e%2e`, `%2E%2e%2f`, `%2f`, `%5c`, `\`, `//`, trailing `/.`, `;`, `%00` → 400, upstream 0 | R5 |
| T6 | Method not in the rule, path one segment too deep for `*`, `/**` boundaries | R2, R5 |
| T7 | Client sends its own `Authorization`, `Cookie`, `X-Goog-Api-Key`, `?key=`, `?KEY=` → upstream sees only the injected credential | R6 |
| T8 | `Host: evil.example`; absolute-form `GET https://evil.example/openrouter/models`; `X-Forwarded-Host`; `CONNECT` → a second "evil" TLS server sees 0 connections and the configured upstream gets the request or a 400 | R1, R7 |
| T9 | `Origin` header → 400; `Host` not a listen address → 400 | R7 |
| T10 | Upstream 302 to another host → 502; the other host sees 0 connections. Same-host 301 → `Location` rewritten to the proxy path | R8 |
| T11 | Upstream echoes the secret in a response header, in the body, across a chunk boundary, as base64 basic, and JSON-escaped → caller sees only same-length redaction; alert logged; `Content-Length` responses still parse | R11 |
| T12 | Log-capture assertion over the whole suite (the JSON log and fd 2), including forced dial and TLS errors on requests carrying `?key=`, and a panic whose value holds a secret. Checked by mutation: logging the request URL fails the run | R10 |
| T13 | SSE: upstream sends 5 events 200 ms apart; the client records arrival times, and each event arrives before the next is sent | R12 |
| T14 | WebSocket with `query` injection: a hand-rolled RFC 6455 client and server in test code (stdlib only) upgrade, exchange frames both ways, upstream sees `key=<real>`, and the log check passes | R13, R10 |
| T15 | Google SA: parse the JWT and verify RS256 with the test public key; check `iss`/`scope`/`aud`/`iat`/`exp`; the fake token endpoint is called once for N requests; fake clock near expiry triggers exactly one refresh under concurrency; bad `token_uri` refuses | R16 |
| T16 | Rate limit: caller A exhausted → 429 for A, B unaffected; unauthenticated flood → 401 only | R15 |
| T17 | Body over the limit → 413, upstream 0 | R14 |
| T18 | Config table: each invalid field is rejected with its path; unknown field rejected; mode 0644 file rejected; `0.0.0.0` without opt-in rejected | R17 |
| T19 | Transport config assertions: `MinVersion`, no `InsecureSkipVerify` (grep test), redirects not followed | R9, R8 |
| T20 | Keychain (macOS only, `-tags keychain_integration`, not in default CI): set/get/rm round trip in a temporary keychain; `key list` returns no data; rebuild and re-sign with the same identity, then read with no prompt | §3 |

**CI** (GitHub Actions on `macos-15`):

- `go vet`, `go test -race ./...`, `govulncheck` (pinned version), `zizmor` on `.github/workflows`, and an `otool -L` check that only `/System/Library` and `/usr/lib` are linked.
- Every action is pinned to a full commit SHA, and `permissions: contents: read` is set at the workflow level.
- Signing isn't done in CI; it's local via `make`.

## 8. Phases

0. This document. **Stop for review.**
1. Config, routing, bearer injection, caller auth, R1 to R12 except streaming specifics, and tests T1 to T12 and T16 to T19 (adversarial tests in the first commit).
2. The header, basic, query and Google SA injectors, SSE, WebSocket, and T13 to T15.
3. The Keychain cgo layer, the CLI with termios, signing, the LaunchAgent plist, the Makefile, and T20.
4. The README, including per-service setup and a "what this does not protect against" section.
