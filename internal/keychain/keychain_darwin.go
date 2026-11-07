package keychain

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#define __STDC_WANT_LIB_EXT1__ 1 // memset_s
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>

// Pointer work stays on this side, so the Go code needs no unsafe.

// cstr returns a malloc'd UTF-8 copy of s, or NULL. The caller frees it.
static char *cstr(CFStringRef s) {
	if (!s) return NULL;
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *b = malloc(n);
	if (b && !CFStringGetCString(s, b, n, kCFStringEncodingUTF8)) { free(b); b = NULL; }
	return b;
}

static void free_str(char *s) { free(s); }

// wipe_free zeroes a secret, then frees it. memset_s is never optimised away.
static void wipe_free(UInt8 *p, size_t n) {
	if (!p) return;
	memset_s(p, n, 0, n);
	free(p);
}

static const void *data_bytes(CFDataRef d) { return CFDataGetBytePtr(d); }

static CFStringRef str(const char *s) {
	return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static void put(CFMutableDictionaryRef d, const void *k, const char *v) {
	CFStringRef s = str(v);
	CFDictionarySetValue(d, k, s);
	CFRelease(s);
}

// query names the generic passwords of service (and account, unless NULL)
// in the keychain file at path, or in the default search list if path is
// NULL. For SecItemAdd, the keychain goes in kSecUseKeychain instead.
static OSStatus query(const char *path, const char *service, const char *account, int adding, CFMutableDictionaryRef *out) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	put(q, kSecAttrService, service);
	if (account) put(q, kSecAttrAccount, account);
	if (path) {
		SecKeychainRef kc;
		OSStatus st = SecKeychainOpen(path, &kc);
		if (st) { CFRelease(q); return st; }
		if (adding) {
			CFDictionarySetValue(q, kSecUseKeychain, kc);
		} else {
			CFArrayRef list = CFArrayCreate(NULL, (const void **)&kc, 1, &kCFTypeArrayCallBacks);
			CFDictionarySetValue(q, kSecMatchSearchList, list);
			CFRelease(list);
		}
		CFRelease(kc);
	}
	*out = q;
	return errSecSuccess;
}

static OSStatus cp_get(const char *path, const char *service, const char *account, CFDataRef *data) {
	CFMutableDictionaryRef q;
	OSStatus st = query(path, service, account, 0, &q);
	if (st) return st;
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	st = SecItemCopyMatching(q, (CFTypeRef *)data);
	CFRelease(q);
	return st;
}

static OSStatus cp_remove(const char *path, const char *service, const char *account) {
	CFMutableDictionaryRef q;
	OSStatus st = query(path, service, account, 0, &q);
	if (st) return st;
	st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// cp_set replaces the item with one whose ACL trusts only the calling
// binary: SecTrustedApplicationCreateFromPath(NULL) is "this process", and
// for signed code it records the designated requirement (DESIGN.md §3).
static OSStatus cp_set(const char *path, const char *service, const char *account, const char *label, const UInt8 *secret, CFIndex len) {
	OSStatus st = cp_remove(path, service, account);
	if (st && st != errSecItemNotFound) return st;

	SecTrustedApplicationRef self;
	if ((st = SecTrustedApplicationCreateFromPath(NULL, &self))) return st;
	CFArrayRef apps = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
	CFStringRef l = str(label);
	SecAccessRef access;
	st = SecAccessCreate(l, apps, &access);
	CFRelease(apps);
	CFRelease(self);
	if (st) { CFRelease(l); return st; }

	CFMutableDictionaryRef q;
	if ((st = query(path, service, account, 1, &q))) { CFRelease(l); CFRelease(access); return st; }
	CFDataRef data = CFDataCreate(NULL, secret, len);
	CFDictionarySetValue(q, kSecAttrLabel, l);
	CFDictionarySetValue(q, kSecAttrAccess, access);
	CFDictionarySetValue(q, kSecValueData, data);
	st = SecItemAdd(q, NULL);
	CFRelease(data);
	CFRelease(q);
	CFRelease(access);
	CFRelease(l);
	return st;
}

// cp_list returns the attributes, never the data, of service's items.
static OSStatus cp_list(const char *path, const char *service, CFArrayRef *items) {
	CFMutableDictionaryRef q;
	OSStatus st = query(path, service, NULL, 0, &q);
	if (st) return st;
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	st = SecItemCopyMatching(q, (CFTypeRef *)items);
	CFRelease(q);
	return st;
}

// cp_account returns item i's account name, for the caller to free.
static char *cp_account(CFArrayRef items, CFIndex i) {
	return cstr(CFDictionaryGetValue(CFArrayGetValueAtIndex(items, i), kSecAttrAccount));
}

// cp_locked reports whether the keychain at path (or the default) is locked.
static int cp_locked(const char *path) {
	SecKeychainRef kc;
	OSStatus st = path ? SecKeychainOpen(path, &kc) : SecKeychainCopyDefault(&kc);
	if (st) return 0;
	SecKeychainStatus status = 0;
	st = SecKeychainGetStatus(kc, &status);
	CFRelease(kc);
	return st == errSecSuccess && !(status & kSecUnlockStateStatus);
}

// cp_self describes this process's own signature. The caller frees *ident.
static OSStatus cp_self(char **ident, CFIndex *certs, uint32_t *flags) {
	*ident = NULL;
	SecCodeRef code;
	OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &code);
	if (st) return st;
	if ((st = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL))) { CFRelease(code); return st; }
	CFDictionaryRef info;
	st = SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSSigningInformation, &info);
	CFRelease(code);
	if (st) return st;
	*ident = cstr(CFDictionaryGetValue(info, kSecCodeInfoIdentifier));
	CFArrayRef chain = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
	*certs = chain ? CFArrayGetCount(chain) : 0;
	CFNumberRef f = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	*flags = 0;
	if (f) CFNumberGetValue(f, kCFNumberSInt32Type, flags);
	CFRelease(info);
	return errSecSuccess;
}
*/
import "C"

import "fmt"

// Keychain is the macOS Keychain: the default search list, or one keychain
// file (tests use a throwaway one).
type Keychain struct{ path string }

func System() *Keychain          { return &Keychain{} }
func Open(path string) *Keychain { return &Keychain{path: path} }

// DisablePrompts makes every Keychain call in this process fail rather than
// show a dialog. serve and key check use it: a daemon must never prompt,
// and a read that would have prompted is reported as ErrDenied.
func DisablePrompts() { C.SecKeychainSetUserInteractionAllowed(0) }

func (k *Keychain) Get(service, account string) ([]byte, error) {
	var data C.CFDataRef
	err := k.call(func(p, s, a *C.char) C.OSStatus { return C.cp_get(p, s, a, &data) }, service, account)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(data))
	return C.GoBytes(C.data_bytes(data), C.int(C.CFDataGetLength(data))), nil
}

// Set stores secret, replacing any item of the same name so the ACL is
// always this binary's.
func (k *Keychain) Set(service, account string, secret []byte) error {
	label := C.CString("credproxy: " + account)
	defer C.free_str(label)
	ptr := (*C.UInt8)(C.CBytes(secret))
	defer C.wipe_free(ptr, C.size_t(len(secret)))
	return k.call(func(p, s, a *C.char) C.OSStatus {
		return C.cp_set(p, s, a, label, ptr, C.CFIndex(len(secret)))
	}, service, account)
}

func (k *Keychain) Remove(service, account string) error {
	return k.call(func(p, s, a *C.char) C.OSStatus { return C.cp_remove(p, s, a) }, service, account)
}

// List returns the account names under service. It asks for attributes
// only, so no secret is ever read.
func (k *Keychain) List(service string) ([]string, error) {
	var items C.CFArrayRef
	err := k.call(func(p, s, _ *C.char) C.OSStatus { return C.cp_list(p, s, &items) }, service, "")
	if err == ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(items))
	var names []string
	for i := range C.CFArrayGetCount(items) {
		if acct := C.cp_account(items, i); acct != nil {
			names = append(names, C.GoString(acct))
			C.free_str(acct)
		}
	}
	return names, nil
}

// call passes path, service and account as C strings (NULL path for the
// search list, NULL account for "every account") and maps the status.
func (k *Keychain) call(f func(path, service, account *C.char) C.OSStatus, service, account string) error {
	var path, acct *C.char
	if k.path != "" {
		path = C.CString(k.path)
		defer C.free_str(path)
	}
	if account != "" {
		acct = C.CString(account)
		defer C.free_str(acct)
	}
	svc := C.CString(service)
	defer C.free_str(svc)
	st := f(path, svc, acct)
	switch {
	case st == C.errSecSuccess:
		return nil
	case st == C.errSecItemNotFound:
		return ErrNotFound
	case C.cp_locked(path) != 0:
		// With prompts off, a locked keychain fails with various statuses.
		return ErrLocked
	case st == C.errSecInteractionNotAllowed, st == C.errSecAuthFailed, st == C.errSecUserCanceled:
		// The item's ACL doesn't trust us, and would have asked.
		return ErrDenied
	}
	return fmt.Errorf("keychain: OSStatus %d", int(st))
}

// Identifier is the signing identifier every item's ACL is pinned to,
// through the designated requirement. The Makefile signs with it.
const Identifier = "com.elicollinson.credproxy"

// CheckSigned refuses to go on unless this binary is validly signed with a
// certificate (not ad-hoc), as Identifier, with the hardened runtime. key
// set uses it so it never creates items pinned to a throwaway build (R18).
func CheckSigned() error {
	var ident *C.char
	var certs C.CFIndex
	var flags C.uint32_t
	st := C.cp_self(&ident, &certs, &flags)
	defer C.free_str(ident)
	if st != C.errSecSuccess {
		return fmt.Errorf("this binary's signature is not valid (OSStatus %d); build it with make", int(st))
	}
	id := C.GoString(ident)
	switch {
	case certs == 0:
		return fmt.Errorf("this binary is ad-hoc signed; build it with make so items survive rebuilds")
	case id != Identifier:
		return fmt.Errorf("this binary is signed as %q, not %q; build it with make", id, Identifier)
	case flags&C.kSecCodeSignatureRuntime == 0:
		return fmt.Errorf("this binary lacks the hardened runtime; build it with make")
	}
	return nil
}
