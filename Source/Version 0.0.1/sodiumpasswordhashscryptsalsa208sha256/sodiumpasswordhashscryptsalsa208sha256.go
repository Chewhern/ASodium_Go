package sodiumpasswordhashscryptsalsa208sha256

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

type OPSLIMIT uint64

const (
	OPSLIMIT_INTERACTIVE OPSLIMIT = 524288
	OPSLIMIT_SENSITIVE   OPSLIMIT = 33554432
)

type MEMLIMIT uint64

const (
	MEMLIMIT_INTERACTIVE MEMLIMIT = 16777216
	MEMLIMIT_SENSITIVE   MEMLIMIT = 1073741824
)

type Strength int

const (
	INTERACTIVE Strength = iota + 1
	SENSITIVE
)

func GetSaltBytesLength() int {
	return int(C.crypto_pwhash_scryptsalsa208sha256_saltbytes())
}

func GetMinDerivedKeyLength() int {
	return int(C.crypto_pwhash_scryptsalsa208sha256_bytes_min())
}

func GetMaxDerivedKeyLength() int {
	return int(C.crypto_pwhash_scryptsalsa208sha256_bytes_max())
}

func GetStrBytesLength() int {
	return int(C.crypto_pwhash_scryptsalsa208sha256_strbytes())
}

func GetMinOpsLimit() uint64 {
	return uint64(C.crypto_pwhash_scryptsalsa208sha256_opslimit_min())
}

func GetMaxOpsLimit() uint64 {
	return uint64(C.crypto_pwhash_scryptsalsa208sha256_opslimit_max())
}

func GetMinMemLimit() uint64 {
	return uint64(C.crypto_pwhash_scryptsalsa208sha256_memlimit_min())
}

func GetMaxMemLimit() uint64 {
	return uint64(C.crypto_pwhash_scryptsalsa208sha256_memlimit_max())
}

func GenerateSalt() []byte {
	return sodiumrng.GetRandomBytes(GetSaltBytesLength())
}

func PBKDF2Strength(
	derivedKeyLength int,
	password []byte,
	salt []byte,
	strength Strength,
	clearkey bool,
) ([]byte, error) {

	if derivedKeyLength == 0 {
		return nil, errors.New("derived key length cannot be 0")
	}

	if derivedKeyLength < GetMinDerivedKeyLength() ||
		derivedKeyLength > GetMaxDerivedKeyLength() {
		return nil, errors.New("invalid derived key length")
	}

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if salt == nil || len(salt) != GetSaltBytesLength() {
		return nil, errors.New("invalid salt length")
	}

	var opslimit, memlimit uint64

	if strength == INTERACTIVE {
		opslimit = (uint64)(OPSLIMIT_INTERACTIVE)
		memlimit = (uint64)(MEMLIMIT_INTERACTIVE)
	} else {
		opslimit = (uint64)(OPSLIMIT_SENSITIVE)
		memlimit = (uint64)(MEMLIMIT_SENSITIVE)
	}

	out := make([]byte, derivedKeyLength)

	rc := C.crypto_pwhash_scryptsalsa208sha256(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.ulonglong(derivedKeyLength),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	if rc != 0 {
		return nil, errors.New("scrypt key derivation failed")
	}

	if clearkey {
		sodiumsecurememory.MemZero(password)
	}

	return out, nil
}

func PBKDF2StrengthPtr(
	derivedKeyLength int,
	password unsafe.Pointer,
	passwordLength int,
	salt []byte,
	strength Strength,
	clearkey bool,
) (unsafe.Pointer, error) {

	if password == nil {
		return nil, errors.New("password pointer cannot be nil")
	}

	if derivedKeyLength == 0 {
		return nil, errors.New("derived key length cannot be 0")
	}

	out, isZero := sodiumguardedheapallocation.SodiumMalloc(derivedKeyLength)

	if isZero == true || out == nil {
		return nil, errors.New("unable to create pointer..")
	}

	var opslimit, memlimit uint64

	if strength == INTERACTIVE {
		opslimit = (uint64)(OPSLIMIT_INTERACTIVE)
		memlimit = (uint64)(MEMLIMIT_INTERACTIVE)
	} else {
		opslimit = (uint64)(OPSLIMIT_SENSITIVE)
		memlimit = (uint64)(MEMLIMIT_SENSITIVE)
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	rc := C.crypto_pwhash_scryptsalsa208sha256(
		(*C.uchar)(out),
		C.ulonglong(derivedKeyLength),
		(*C.char)(password),
		C.ulonglong(passwordLength),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearkey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	if rc != 0 {
		return nil, errors.New("scrypt key derivation failed")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(out)

	return out, nil
}

func CustomPBKDF2(
	derivedKeyLength int,
	password []byte,
	salt []byte,
	opslimit uint64,
	memlimit uint64,
	clearkey bool,
) ([]byte, error) {

	if derivedKeyLength == 0 {
		return nil, errors.New("derived key length cannot be 0")
	}

	if derivedKeyLength < GetMinDerivedKeyLength() ||
		derivedKeyLength > GetMaxDerivedKeyLength() {
		return nil, errors.New("invalid derived key length")
	}

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if salt == nil || len(salt) != GetSaltBytesLength() {
		return nil, errors.New("invalid salt length")
	}

	if opslimit == 0 ||
		opslimit < GetMinOpsLimit() ||
		opslimit > GetMaxOpsLimit() {
		return nil, errors.New("invalid ops limit")
	}

	if memlimit == 0 ||
		memlimit < GetMinMemLimit() ||
		memlimit > GetMaxMemLimit() {
		return nil, errors.New("invalid mem limit")
	}

	out := make([]byte, derivedKeyLength)

	rc := C.crypto_pwhash_scryptsalsa208sha256(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.ulonglong(derivedKeyLength),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	if rc != 0 {
		return nil, errors.New("scrypt key derivation failed")
	}

	if clearkey {
		sodiumsecurememory.MemZero(password)
	}

	return out, nil
}

func CustomPBKDF2Ptr(
	derivedKeyLength int,
	password unsafe.Pointer,
	passwordLength int,
	salt []byte,
	opslimit uint64,
	memlimit uint64,
	clearkey bool,
) (unsafe.Pointer, error) {

	if password == nil {
		return nil, errors.New("password pointer cannot be nil")
	}

	if derivedKeyLength == 0 {
		return nil, errors.New("derived key length cannot be 0")
	}

	out, isZero := sodiumguardedheapallocation.SodiumMalloc(derivedKeyLength)

	if isZero == true || out == nil {
		return nil, errors.New("unable to create pointer..")
	}

	if opslimit == 0 ||
		opslimit < GetMinOpsLimit() ||
		opslimit > GetMaxOpsLimit() {
		return nil, errors.New("invalid ops limit")
	}

	if memlimit == 0 ||
		memlimit < (uint64)(GetMinMemLimit()) ||
		memlimit > (uint64)(GetMaxMemLimit()) {
		return nil, errors.New("invalid mem limit")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	rc := C.crypto_pwhash_scryptsalsa208sha256(
		(*C.uchar)(out),
		C.ulonglong(derivedKeyLength),
		(*C.char)(password),
		C.ulonglong(passwordLength),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearkey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	if rc != 0 {
		return nil, errors.New("scrypt key derivation failed")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(out)

	return out, nil
}

func ComputePasswordHash(
	password []byte,
	strength Strength,
	clearkey bool,
) (string, error) {

	if len(password) == 0 {
		return "", errors.New("password cannot be empty")
	}

	var opslimit, memlimit uint64

	if strength == INTERACTIVE {
		opslimit = (uint64)(OPSLIMIT_INTERACTIVE)
		memlimit = (uint64)(MEMLIMIT_INTERACTIVE)
	} else {
		opslimit = (uint64)(OPSLIMIT_SENSITIVE)
		memlimit = (uint64)(MEMLIMIT_SENSITIVE)
	}

	hashBuf := make([]byte, GetStrBytesLength())

	rc := C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&hashBuf[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	if clearkey {
		sodiumsecurememory.MemZero(password)
	}

	if rc != 0 {
		return "", errors.New("password hashing failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&hashBuf[0]))), nil
}

func ComputePasswordHashPtr(
	password unsafe.Pointer,
	passwordlen int64,
	strength Strength,
	clearkey bool,
) (string, error) {

	if password == nil {
		return "", errors.New("password cannot be empty")
	}

	var opslimit, memlimit uint64

	if strength == INTERACTIVE {
		opslimit = (uint64)(OPSLIMIT_INTERACTIVE)
		memlimit = (uint64)(MEMLIMIT_INTERACTIVE)
	} else {
		opslimit = (uint64)(OPSLIMIT_SENSITIVE)
		memlimit = (uint64)(MEMLIMIT_SENSITIVE)
	}

	hashBuf := make([]byte, GetStrBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	rc := C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&hashBuf[0])),
		(*C.char)(password),
		C.ulonglong(passwordlen),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearkey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	if rc != 0 {
		return "", errors.New("password hashing failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&hashBuf[0]))), nil
}

func CustomComputePasswordHash(
	password []byte,
	opslimit uint64,
	memlimit uint64,
	clearkey bool,
) (string, error) {

	if len(password) == 0 {
		return "", errors.New("password cannot be empty")
	}

	if opslimit == 0 ||
		opslimit < GetMinOpsLimit() ||
		opslimit > GetMaxOpsLimit() {
		return "", errors.New("invalid ops limit")
	}

	if memlimit == 0 ||
		memlimit < (uint64)(GetMinMemLimit()) ||
		memlimit > (uint64)(GetMaxMemLimit()) {
		return "", errors.New("invalid mem limit")
	}

	hashBuf := make([]byte, GetStrBytesLength())

	rc := C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&hashBuf[0])),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	if clearkey {
		sodiumsecurememory.MemZero(password)
	}

	if rc != 0 {
		return "", errors.New("password hashing failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&hashBuf[0]))), nil
}

func CustomComputePasswordHashPtr(
	password unsafe.Pointer,
	passwordlen int64,
	opslimit uint64,
	memlimit uint64,
	clearkey bool,
) (string, error) {

	if password == nil {
		return "", errors.New("password cannot be empty")
	}

	if opslimit == 0 ||
		opslimit < GetMinOpsLimit() ||
		opslimit > GetMaxOpsLimit() {
		return "", errors.New("invalid ops limit")
	}

	if memlimit == 0 ||
		memlimit < (uint64)(GetMinMemLimit()) ||
		memlimit > (uint64)(GetMaxMemLimit()) {
		return "", errors.New("invalid mem limit")
	}

	hashBuf := make([]byte, GetStrBytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	rc := C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&hashBuf[0])),
		(*C.char)(password),
		C.ulonglong(passwordlen),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearkey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	if rc != 0 {
		return "", errors.New("password hashing failed")
	}

	return C.GoString((*C.char)(unsafe.Pointer(&hashBuf[0]))), nil
}

func VerifyPassword(
	hashed string,
	password []byte,
	clearkey bool,
) (bool, error) {

	if len(hashed) == 0 {
		return false, errors.New("hashed password string cannot be empty")
	}

	if len(password) == 0 {
		return false, errors.New("password cannot be empty")
	}

	rc := C.crypto_pwhash_scryptsalsa208sha256_str_verify(
		(C.CString)(hashed),
		(*C.char)(unsafe.Pointer(&password[0])),
		C.ulonglong(len(password)),
	)

	if clearkey {
		sodiumsecurememory.MemZero(password)
	}

	return rc == 0, nil
}

func VerifyPasswordPtr(
	hashed string,
	password unsafe.Pointer,
	passwordLength int,
	clearkey bool,
) (bool, error) {

	if password == nil {
		return false, errors.New("password pointer cannot be nil")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(password)

	rc := C.crypto_pwhash_scryptsalsa208sha256_str_verify(
		(C.CString)(hashed),
		(*C.char)(password),
		C.ulonglong(passwordLength),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(password)

	if clearkey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(password)
		sodiumguardedheapallocation.SodiumFree(password)
	}

	return rc == 0, nil
}

func PasswordNeedsRehashCustom(
	hashed string,
	opslimit uint64,
	memlimit uint64,
) (int, error) {

	if len(hashed) == 0 {
		return -1, errors.New("hashed password string cannot be empty")
	}

	rc := C.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
		C.CString(hashed),
		C.ulonglong(opslimit),
		C.size_t(memlimit),
	)

	return int(rc), nil
}
