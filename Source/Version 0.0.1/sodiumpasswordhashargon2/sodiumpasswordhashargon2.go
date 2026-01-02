package sodiumpasswordhashargon2

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumrng"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

type Algorithm int

const (
	ARGON2I  Algorithm = C.crypto_pwhash_ALG_ARGON2I13
	ARGON2ID Algorithm = C.crypto_pwhash_ALG_ARGON2ID13
	DEFAULT  Algorithm = ARGON2ID
)

type OPSLIMIT uint64

const (
	OPSLIMIT_INTERACTIVE OPSLIMIT = C.crypto_pwhash_OPSLIMIT_INTERACTIVE
	OPSLIMIT_MODERATE    OPSLIMIT = C.crypto_pwhash_OPSLIMIT_MODERATE
	OPSLIMIT_SENSITIVE   OPSLIMIT = C.crypto_pwhash_OPSLIMIT_SENSITIVE
)

type MEMLIMIT uint64

const (
	MEMLIMIT_INTERACTIVE MEMLIMIT = C.crypto_pwhash_MEMLIMIT_INTERACTIVE
	MEMLIMIT_MODERATE    MEMLIMIT = C.crypto_pwhash_MEMLIMIT_MODERATE
	MEMLIMIT_SENSITIVE   MEMLIMIT = C.crypto_pwhash_MEMLIMIT_SENSITIVE
)

type Strength int

const (
	INTERACTIVE Strength = iota + 1
	MODERATE
	SENSITIVE
)

func GetMinPBKDFLength() int {
	return int(C.crypto_pwhash_bytes_min())
}

func GetMaxPBKDFLength() int64 {
	return int64(C.crypto_pwhash_bytes_max())
}

func GetMinPasswordLength() int {
	return int(C.crypto_pwhash_passwd_min())
}

func GetMaxPasswordLength() int64 {
	return int64(C.crypto_pwhash_passwd_max())
}

func GetSaltBytesLength() int {
	return int(C.crypto_pwhash_saltbytes())
}

func GetMinOpsLimit() uint64 {
	return uint64(C.crypto_pwhash_opslimit_min())
}

func GetMaxOpsLimit() uint64 {
	return uint64(C.crypto_pwhash_opslimit_max())
}

func GetMinMemLimit() int64 {
	return int64(C.crypto_pwhash_memlimit_min())
}

func GetMaxMemLimit() int64 {
	return int64(C.crypto_pwhash_memlimit_max())
}

func GetHashedPasswordWithArgumentLength() int {
	return int(C.crypto_pwhash_strbytes())
}

func GenerateSalt() []byte {
	salt := sodiumrng.GetRandomBytes(GetSaltBytesLength())

	return salt
}

func Argon2PBKDFCustom(
	derivedKeyLength int,
	password []byte,
	salt []byte,
	opsLimit uint64,
	memLimit int64,
	algorithm Algorithm,
	clearKey bool,
) ([]byte, error) {

	// ---- Derived key length checks ----
	if derivedKeyLength <= 0 {
		return nil, errors.New("derived key length cannot be 0")
	}
	if derivedKeyLength < GetMinPBKDFLength() ||
		int64(derivedKeyLength) > GetMaxPBKDFLength() {
		return nil, errors.New("invalid derived key length")
	}

	// ---- Password checks ----
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if int64(len(password)) > GetMaxPasswordLength() {
		return nil, errors.New("password too long")
	}

	// ---- Salt checks ----
	if salt == nil {
		return nil, errors.New("salt cannot be nil")
	}
	if len(salt) != GetSaltBytesLength() {
		return nil, errors.New("invalid salt length")
	}

	// ---- OpsLimit checks ----
	if opsLimit == 0 {
		return nil, errors.New("ops limit cannot be 0")
	}
	if opsLimit < GetMinOpsLimit() || opsLimit > GetMaxOpsLimit() {
		return nil, errors.New("invalid ops limit")
	}

	// ---- MemLimit checks ----
	if memLimit == 0 {
		return nil, errors.New("mem limit cannot be 0")
	}
	if memLimit < GetMinMemLimit() || memLimit > GetMaxMemLimit() {
		return nil, errors.New("invalid mem limit")
	}

	// ---- Allocate output ----
	derivedKey := make([]byte, derivedKeyLength)

	alg := algorithm
	if alg == DEFAULT {
		alg = ARGON2ID
	}

	// ---- Call libsodium ----
	ret := C.crypto_pwhash(
		(*C.uchar)(unsafe.Pointer(&derivedKey[0])),
		C.ulonglong(derivedKeyLength),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
		C.int(alg),
	)

	// ---- Clear password if requested ----
	if clearKey {
		sodiumsecurememory.MemZero(password)
	}

	if ret != 0 {
		return nil, errors.New("failed to derive key from password")
	}

	return derivedKey, nil
}

func Argon2PBKDFCustomPtr(
	derivedKeyLen int,
	passwordPtr unsafe.Pointer,
	passwordLen int,
	salt []byte,
	opsLimit uint64,
	memLimit int64,
	algorithm Algorithm,
	clearKey bool,
) (unsafe.Pointer, error) {

	if passwordPtr == nil {
		return nil, errors.New("password pointer is null")
	}

	if salt == nil || len(salt) != GetSaltBytesLength() {
		return nil, errors.New("invalid salt length")
	}

	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(derivedKeyLen)
	if keyPtr == nil || isZero == true {
		return nil, errors.New("sodium_malloc failed")
	}

	rc := C.crypto_pwhash(
		(*C.uchar)(keyPtr),
		C.size_t(derivedKeyLen),
		(*C.char)(passwordPtr),
		C.size_t(passwordLen),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
		C.int(algorithm),
	)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(passwordPtr)
		sodiumguardedheapallocation.SodiumFree(passwordPtr)
	}

	if rc != 0 {
		sodiumguardedheapallocation.SodiumFree(keyPtr)
		return nil, errors.New("argon2 key derivation failed")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	return keyPtr, nil
}

func Argon2PBKDF(
	derivedKeyLen int,
	password []byte,
	salt []byte,
	strength Strength,
	algorithm Algorithm,
	clearKey bool,
) ([]byte, error) {

	var ops uint64
	var mem int64

	switch strength {
	case INTERACTIVE:
		ops = (uint64)(OPSLIMIT_INTERACTIVE)
		mem = (int64)(MEMLIMIT_INTERACTIVE)
	case MODERATE:
		ops = (uint64)(OPSLIMIT_MODERATE)
		mem = (int64)(MEMLIMIT_MODERATE)
	case SENSITIVE:
		ops = (uint64)(OPSLIMIT_SENSITIVE)
		mem = (int64)(MEMLIMIT_SENSITIVE)
	default:
		return nil, errors.New("invalid strength")
	}

	return Argon2PBKDFCustom(
		derivedKeyLen,
		password,
		salt,
		ops,
		mem,
		algorithm,
		clearKey,
	)
}

func Argon2PBKDFPtr(
	derivedKeyLength int64,
	password unsafe.Pointer,
	passwordLength int64,
	salt []byte,
	strength Strength,
	algorithm Algorithm,
	clearKey bool,
) (unsafe.Pointer, error) {

	if derivedKeyLength == 0 {
		return nil, errors.New("derived key length cannot be 0")
	}
	if derivedKeyLength < int64(GetMinPBKDFLength()) || derivedKeyLength > GetMaxPBKDFLength() {
		return nil, errors.New("invalid derived key length")
	}
	if password == nil {
		return nil, errors.New("password cannot be null")
	}
	if salt == nil || len(salt) != GetSaltBytesLength() {
		return nil, errors.New("invalid salt")
	}

	var ops uint64
	var mem int64

	switch strength {
	case INTERACTIVE:
		ops = (uint64)(OPSLIMIT_INTERACTIVE)
		mem = (int64)(MEMLIMIT_INTERACTIVE)
	case MODERATE:
		ops = (uint64)(OPSLIMIT_MODERATE)
		mem = (int64)(MEMLIMIT_MODERATE)
	case SENSITIVE:
		ops = (uint64)(OPSLIMIT_SENSITIVE)
		mem = (int64)(MEMLIMIT_SENSITIVE)
	default:
		return nil, errors.New("invalid strength")
	}

	derivedKey, isZero := sodiumguardedheapallocation.SodiumMalloc(int(derivedKeyLength))
	if isZero == true || derivedKey == nil {
		return nil, nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	var alg C.int
	if algorithm == ARGON2I {
		alg = C.crypto_pwhash_ALG_ARGON2I13
	} else {
		alg = C.crypto_pwhash_ALG_ARGON2ID13
	}

	ret := C.crypto_pwhash(
		(*C.uchar)(derivedKey),
		C.size_t(derivedKeyLength),
		(*C.char)(password),
		C.ulonglong(passwordLength),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(ops),
		C.ulonglong(mem),
		alg,
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	if ret != 0 {
		return nil, errors.New("argon2 pbkdf failed")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(derivedKey)
	return derivedKey, nil
}

func Argon2HashPassword(
	password []byte,
	strength Strength,
	clearKey bool,
) (string, error) {

	if len(password) == 0 {
		return "", errors.New("password cannot be empty")
	}
	if int64(len(password)) > GetMaxPasswordLength() {
		return "", errors.New("password too long")
	}

	out := make([]byte, GetHashedPasswordWithArgumentLength())

	var ops uint64
	var mem int64

	switch strength {
	case INTERACTIVE:
		ops = (uint64)(OPSLIMIT_INTERACTIVE)
		mem = (int64)(MEMLIMIT_INTERACTIVE)
	case MODERATE:
		ops = (uint64)(OPSLIMIT_MODERATE)
		mem = (int64)(MEMLIMIT_MODERATE)
	case SENSITIVE:
		ops = (uint64)(OPSLIMIT_SENSITIVE)
		mem = (int64)(MEMLIMIT_SENSITIVE)
	default:
		return "", errors.New("invalid strength")
	}

	ret := C.crypto_pwhash_str(
		(*C.char)(unsafe.Pointer(&out[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		C.ulonglong(ops),
		C.ulonglong(mem),
	)

	if clearKey {
		sodiumsecurememory.MemZero(password)
	}

	if ret != 0 {
		return "", errors.New("argon2 password hash failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&out[0]))), nil
}

func Argon2HashPasswordPtr(
	password unsafe.Pointer,
	passwordLen int64,
	strength Strength,
	clearKey bool,
) (string, error) {

	if password == nil {
		return "", errors.New("password cannot be null")
	}

	buf := make([]byte, GetHashedPasswordWithArgumentLength())

	var ops uint64
	var mem int64

	switch strength {
	case INTERACTIVE:
		ops = (uint64)(OPSLIMIT_INTERACTIVE)
		mem = (int64)(MEMLIMIT_INTERACTIVE)
	case MODERATE:
		ops = (uint64)(OPSLIMIT_MODERATE)
		mem = (int64)(MEMLIMIT_MODERATE)
	case SENSITIVE:
		ops = (uint64)(OPSLIMIT_SENSITIVE)
		mem = (int64)(MEMLIMIT_SENSITIVE)
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)
	ret := C.crypto_pwhash_str(
		(*C.char)(unsafe.Pointer(&buf[0])),
		(*C.char)(password),
		C.ulonglong(passwordLen),
		C.ulonglong(ops),
		C.ulonglong(mem),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if ret != 0 {
		return "", errors.New("argon2 hashing failed")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

func Argon2CustomParamHashPassword(
	password []byte,
	opsLimit uint64,
	memLimit int64,
	clearKey bool,
) (string, error) {

	if len(password) == 0 {
		return "", errors.New("password cannot be null")
	}
	if int64(len(password)) > GetMaxPasswordLength() {
		return "", errors.New("password too long")
	}
	if opsLimit < GetMinOpsLimit() || opsLimit > GetMaxOpsLimit() {
		return "", errors.New("invalid ops limit")
	}
	if memLimit < GetMinMemLimit() || memLimit > GetMaxMemLimit() {
		return "", errors.New("invalid mem limit")
	}

	buf := make([]byte, GetHashedPasswordWithArgumentLength())

	ret := C.crypto_pwhash_str(
		(*C.char)(unsafe.Pointer(&buf[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
	)

	if clearKey {
		for i := range password {
			password[i] = 0
		}
	}

	if ret != 0 {
		return "", errors.New("argon2 hashing failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

func Argon2CustomParamHashPasswordPtr(
	password unsafe.Pointer,
	passwordLen int64,
	opsLimit uint64,
	memLimit int64,
	clearKey bool,
) (string, error) {

	if opsLimit == 0 {
		return "", errors.New("error: ops limit cannot be 0")
	}
	if opsLimit < GetMinOpsLimit() || opsLimit > GetMaxOpsLimit() {
		return "", errors.New("error: ops limit out of range")
	}
	if memLimit == 0 {
		return "", errors.New("error: mem limit cannot be 0")
	}
	if memLimit < GetMinMemLimit() || memLimit > GetMaxMemLimit() {
		return "", errors.New("error: mem limit out of range")
	}
	if password == nil {
		return "", errors.New("error: password cannot be null")
	}

	hashed := make([]byte, GetHashedPasswordWithArgumentLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)
	rc := C.crypto_pwhash_str(
		(*C.char)(unsafe.Pointer(&hashed[0])),
		(*C.char)(password),
		C.ulonglong(passwordLen),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if rc != 0 {
		return "", errors.New("error: password failed to hash with argon")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	return string(hashed), nil
}

func VerifyPasswordString(
	hashed string,
	password []byte,
	clearKey bool,
) (bool, error) {

	if len(hashed) != GetHashedPasswordWithArgumentLength() {
		return false, errors.New("error: invalid hashed password length")
	}
	if len(password) == 0 || int64(len(password)) > GetMaxPasswordLength() {
		return false, errors.New("error: invalid password length")
	}

	rc := C.crypto_pwhash_str_verify(
		C.CString(hashed),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
	)

	if clearKey {
		sodiumsecurememory.MemZero(password)
	}

	return rc == 0, nil
}

func VerifyPasswordStringPtr(
	hashed string,
	password unsafe.Pointer,
	passwordLen int64,
	clearKey bool,
) (bool, error) {

	if len(hashed) != GetHashedPasswordWithArgumentLength() {
		return false, errors.New("error: invalid hashed password length")
	}
	if password == nil {
		return false, errors.New("error: password cannot be null")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)
	rc := C.crypto_pwhash_str_verify(
		C.CString(hashed),
		(*C.char)(password),
		C.ulonglong(passwordLen),
	)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	return rc == 0, nil
}

// CustomParamsPasswordNeedsRehash
func CustomParamsPasswordNeedsRehash(
	hashed string,
	opsLimit uint64,
	memLimit int64,
) (int, error) {

	if len(hashed) != GetHashedPasswordWithArgumentLength() {
		return 0, errors.New("error: invalid hashed password length")
	}
	if opsLimit == 0 || opsLimit < GetMinOpsLimit() || opsLimit > GetMaxOpsLimit() {
		return 0, errors.New("error: ops limit out of range")
	}
	if memLimit == 0 || memLimit < GetMinMemLimit() || memLimit > GetMaxMemLimit() {
		return 0, errors.New("error: mem limit out of range")
	}

	rc := C.crypto_pwhash_str_needs_rehash(
		C.CString(hashed),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
	)

	return int(rc), nil
}

// PasswordNeedsRehash (strength-based)
func PasswordNeedsRehash(
	hashed string,
	strength Strength,
) (int, error) {

	if len(hashed) != GetHashedPasswordWithArgumentLength() {
		return 0, errors.New("error: invalid hashed password length")
	}

	var opsLimit uint64
	var memLimit int64

	switch strength {
	case INTERACTIVE:
		opsLimit = uint64(OPSLIMIT_INTERACTIVE)
		memLimit = int64(MEMLIMIT_INTERACTIVE)
	case MODERATE:
		opsLimit = uint64(OPSLIMIT_MODERATE)
		memLimit = int64(MEMLIMIT_MODERATE)
	default:
		opsLimit = uint64(OPSLIMIT_SENSITIVE)
		memLimit = int64(MEMLIMIT_SENSITIVE)
	}

	rc := C.crypto_pwhash_str_needs_rehash(
		C.CString(hashed),
		C.ulonglong(opsLimit),
		C.size_t(memLimit),
	)

	return int(rc), nil
}
