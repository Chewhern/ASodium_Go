package sodiumhelper

// #cgo pkg-config: libsodium
// #include <sodium.h>
// #include <stdlib.h>
import "C"
import (
	"ASodium/sodiumguardedheapallocation"
	"errors"
	"unsafe"
)

func SodiumMemoryCompare(a, b []byte) error {
	if a == nil || b == nil {
		return errors.New("ByteArray1 and ByteArray2 must not be null")
	}
	if len(a) != len(b) {
		return errors.New("ByteArray1 and ByteArray2 must be the same length")
	}

	if C.sodium_memcmp(
		unsafe.Pointer(&a[0]),
		unsafe.Pointer(&b[0]),
		C.size_t(len(a)),
	) != 0 {
		return errors.New("two byte arrays do not match")
	}
	return nil
}

func SodiumMemoryComparePtr(a, b unsafe.Pointer, length int) error {
	if a == nil || b == nil {
		return errors.New("ByteArray1 and ByteArray2 must not be null")
	}

	sodiumguardedheapallocation.SodiumMProtectReadWrite(a)
	sodiumguardedheapallocation.SodiumMProtectReadWrite(b)

	result := C.sodium_memcmp(a, b, C.size_t(length))

	sodiumguardedheapallocation.SodiumMProtectNoAccess(a)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(b)

	if result != 0 {
		return errors.New("two byte arrays do not match")
	}
	return nil
}

type Base64Variant int

const (
	Base64Original          Base64Variant = 1
	Base64OriginalNoPadding Base64Variant = 3
	Base64UrlSafe           Base64Variant = 5
	Base64UrlSafeNoPadding  Base64Variant = 7
)

func BinaryToHex(data []byte) (string, error) {
	if data == nil {
		return "", errors.New("data is nil")
	}

	hexLen := len(data)*2 + 1
	buf := make([]byte, hexLen)

	ptr := C.sodium_bin2hex(
		(*C.char)(unsafe.Pointer(&buf[0])),
		C.size_t(hexLen),
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)

	if ptr == nil {
		return "", errors.New("encoding failed")
	}
	return C.GoString(ptr), nil
}

func HexToBinary(hex string) ([]byte, error) {
	const ignored = ":- "

	if hex == "" {
		return []byte{}, nil
	}

	out := make([]byte, len(hex)/2)
	var binLen C.size_t

	ret := C.sodium_hex2bin(
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		C.CString(hex),
		C.size_t(len(hex)),
		C.CString(ignored),
		&binLen,
		nil,
	)

	if ret != 0 {
		return nil, errors.New("decoding failed")
	}

	return out[:binLen], nil
}

func BinaryToBase64(data []byte, variant Base64Variant) (string, error) {
	if data == nil {
		return "", errors.New("data is nil")
	}
	if len(data) == 0 {
		return "", nil
	}

	maxLen := C.sodium_base64_encoded_len(
		C.size_t(len(data)),
		C.int(variant),
	)

	buf := make([]byte, maxLen)

	ptr := C.sodium_bin2base64(
		(*C.char)(unsafe.Pointer(&buf[0])),
		maxLen,
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		C.int(variant),
	)

	if ptr == nil {
		return "", errors.New("encoding failed")
	}

	return C.GoString(ptr), nil
}

func Base64ToBinary(base64 string, ignored string, variant Base64Variant) ([]byte, error) {
	if base64 == "" {
		return []byte{}, nil
	}

	buf := make([]byte, len(base64))
	var binLen C.size_t
	var b64End *C.char

	cBase64 := C.CString(base64)
	defer C.free(unsafe.Pointer(cBase64))

	var cIgnored *C.char
	if ignored != "" {
		cIgnored = C.CString(ignored)
		defer C.free(unsafe.Pointer(cIgnored))
	}

	ret := C.sodium_base642bin(
		(*C.uchar)(unsafe.Pointer(&buf[0])),
		C.size_t(len(buf)),
		cBase64,
		C.size_t(len(base64)),
		cIgnored,
		&binLen,
		&b64End,
		C.int(variant),
	)

	if ret != 0 {
		return nil, errors.New("decoding failed")
	}

	return buf[:binLen], nil
}

func SodiumIncrement(n []byte) []byte {
	C.sodium_increment(
		(*C.uchar)(unsafe.Pointer(&n[0])),
		C.size_t(len(n)),
	)
	return n
}

func SodiumIncrementPtr(ptr unsafe.Pointer, length int) unsafe.Pointer {
	sodiumguardedheapallocation.SodiumMProtectReadWrite(ptr)
	C.sodium_increment((*C.uchar)(ptr), C.size_t(length))
	return ptr
}

func SodiumAdd(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("numbers must have same length")
	}

	C.sodium_add(
		(*C.uchar)(unsafe.Pointer(&a[0])),
		(*C.uchar)(unsafe.Pointer(&b[0])),
		C.size_t(len(a)),
	)
	return a, nil
}

func SodiumAddPtr(a, b unsafe.Pointer, length int) unsafe.Pointer {
	sodiumguardedheapallocation.SodiumMProtectReadWrite(a)
	sodiumguardedheapallocation.SodiumMProtectReadOnly(b)

	C.sodium_add((*C.uchar)(a), (*C.uchar)(b), C.size_t(length))
	return a
}

func SodiumSub(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("numbers must have same length")
	}

	C.sodium_sub(
		(*C.uchar)(unsafe.Pointer(&a[0])),
		(*C.uchar)(unsafe.Pointer(&b[0])),
		C.size_t(len(a)),
	)
	return a, nil
}

func SodiumSubPtr(a, b unsafe.Pointer, length int) unsafe.Pointer {
	sodiumguardedheapallocation.SodiumMProtectReadWrite(a)
	sodiumguardedheapallocation.SodiumMProtectReadOnly(b)

	C.sodium_sub((*C.uchar)(a), (*C.uchar)(b), C.size_t(length))
	return a
}

func SodiumCompare(a, b []byte) int {
	return int(C.sodium_compare(
		(*C.uchar)(unsafe.Pointer(&a[0])),
		(*C.uchar)(unsafe.Pointer(&b[0])),
		C.size_t(len(a)),
	))
}

func SodiumComparePtr(a, b unsafe.Pointer, length int) int {
	sodiumguardedheapallocation.SodiumMProtectReadOnly(a)
	sodiumguardedheapallocation.SodiumMProtectReadOnly(b)

	return int(C.sodium_compare((*C.uchar)(a), (*C.uchar)(b), C.size_t(length)))
}

func SodiumStackZero(length int) {
	C.sodium_stackzero(C.size_t(length))
}
