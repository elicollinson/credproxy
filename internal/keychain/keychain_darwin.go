package keychain

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <Security/Security.h>

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

static CFStringRef cp_account(CFArrayRef items, CFIndex i) {
	return CFDictionaryGetValue(CFArrayGetValueAtIndex(items, i), kSecAttrAccount);
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

// cp_self describes this process's own signature.
static OSStatus cp_self(char *ident, CFIndex n, CFIndex *certs, uint32_t *flags) {
	SecCodeRef code;
	OSStatus st = SecCodeCopySelf(kSecCSDefaultFlags, &code);
	if (st) return st;
	if ((st = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL))) { CFRelease(code); return st; }
	CFDictionaryRef info;
	st = SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSSigningInformation, &info);
	CFRelease(code);
	if (st) return st;
	ident[0] = 0;
	CFStringRef id = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if (id) CFStringGetCString(id, ident, n, kCFStringEncodingUTF8);
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

import (
	"fmt"
	"unsafe"
)

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
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data))), nil
}

// Set stores secret, replacing any item of the same name so the ACL is
// always this binary's.
func (k *Keychain) Set(service, account string, secret []byte) error {
	label := C.CString("credproxy: " + account)
	defer C.free(unsafe.Pointer(label))
	ptr := (*C.UInt8)(C.CBytes(secret))
	defer func() {
		clear(unsafe.Slice((*byte)(ptr), len(secret)))
		C.free(unsafe.Pointer(ptr))
	}()
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
	buf := make([]byte, 1024)
	for i := range C.CFArrayGetCount(items) {
		acct := C.cp_account(items, i)
		if acct != 0 && C.CFStringGetCString(acct, (*C.char)(unsafe.Pointer(&buf[0])), C.CFIndex(len(buf)), C.kCFStringEncodingUTF8) != 0 {
			names = append(names, C.GoString((*C.char)(unsafe.Pointer(&buf[0]))))
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
		defer C.free(unsafe.Pointer(path))
	}
	if account != "" {
		acct = C.CString(account)
		defer C.free(unsafe.Pointer(acct))
	}
	svc := C.CString(service)
	defer C.free(unsafe.Pointer(svc))
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
	ident := make([]byte, 256)
	var certs C.CFIndex
	var flags C.uint32_t
	if st := C.cp_self((*C.char)(unsafe.Pointer(&ident[0])), C.CFIndex(len(ident)), &certs, &flags); st != C.errSecSuccess {
		return fmt.Errorf("this binary's signature is not valid (OSStatus %d); build it with make", int(st))
	}
	id := C.GoString((*C.char)(unsafe.Pointer(&ident[0])))
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
