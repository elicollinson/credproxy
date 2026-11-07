# The signing identity is the one thing to set. Every Keychain item trusts
# the designated requirement it produces, so keep using the same one
# (DESIGN.md §3). `make cert` explains how to make it.
SIGN_IDENTITY ?= credproxy-signing

IDENTIFIER := com.elicollinson.credproxy
LABEL      := $(IDENTIFIER)
BIN        ?= bin/credproxy
PREFIX     ?= $(HOME)/.local
CONFIG     ?= $(HOME)/.config/credproxy/config.json
PLIST      := $(HOME)/Library/LaunchAgents/$(LABEL).plist
LOG        := $(HOME)/Library/Logs/credproxy.log
DOMAIN     := gui/$(shell id -u)

.PHONY: build test test-keychain install uninstall cert

# Signed with the hardened runtime and no entitlements, so no get-task-allow:
# other processes of the same user can't attach a debugger or inject a
# dylib (R18).
build:
	go build -trimpath $(GOBUILDFLAGS) -o $(BIN) ./cmd/credproxy
	codesign --force --sign "$(SIGN_IDENTITY)" --identifier $(IDENTIFIER) --options runtime --timestamp=none $(BIN)
	codesign --verify --strict $(BIN)

test:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

# T20: the real Keychain, in a throwaway keychain file.
test-keychain:
	SIGN_IDENTITY="$(SIGN_IDENTITY)" go test -tags keychain_integration -run TestKeychain -count=1 -v ./cmd/credproxy

# Installs to $(PREFIX)/bin and runs as a LaunchAgent in your GUI session,
# where the login keychain is unlocked. install -S replaces the binary by
# rename, never in place under a running process.
install: build
	install -d $(PREFIX)/bin $(dir $(PLIST)) $(dir $(LOG))
	install -S -m 0755 $(BIN) $(PREFIX)/bin/credproxy
	$(PREFIX)/bin/credproxy config check -config $(CONFIG)
	sed -e 's|@LABEL@|$(LABEL)|' -e 's|@BIN@|$(PREFIX)/bin/credproxy|' -e 's|@CONFIG@|$(CONFIG)|' -e 's|@LOG@|$(LOG)|' \
		packaging/launchagent.plist.tmpl > $(PLIST)
	launchctl bootout $(DOMAIN)/$(LABEL) 2>/dev/null || true
	launchctl bootstrap $(DOMAIN) $(PLIST)
	@echo "credproxy is running; logs in $(LOG)"

uninstall:
	launchctl bootout $(DOMAIN)/$(LABEL) 2>/dev/null || true
	rm -f $(PLIST) $(PREFIX)/bin/credproxy

cert:
	@echo 'Create the signing certificate once, on this Mac:'
	@echo '  1. Keychain Access > Certificate Assistant > Create a Certificate...'
	@echo '  2. Name: credproxy-signing; Identity Type: Self Signed Root; Certificate Type: Code Signing'
	@echo '     Tick "Let me override defaults" and set the validity to 3650 days. Save it in the login keychain.'
	@echo '  3. Open the certificate, expand Trust, set Code Signing to Always Trust.'
	@echo '  4. Check: security find-identity -v -p codesigning'
	@echo 'Back it up (Export as .p12): a new certificate means running key set again for every key.'
