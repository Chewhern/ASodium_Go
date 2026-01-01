package memcpyhelper

// #include <string.h>
import "C"
import (
	"unsafe"
)

func PtrCopyBytesToBytes(src unsafe.Pointer, n int) []byte {
	if src == nil || n <= 0 {
		return nil
	}

	buf := make([]byte, n)
	C.memcpy(
		unsafe.Pointer(&buf[0]),
		src,
		C.size_t(n),
	)

	return buf
}

func BytesCopyToPtr(src []byte, dst unsafe.Pointer) {
	if dst == nil || len(src) == 0 {
		return
	}

	C.memcpy(
		dst,
		unsafe.Pointer(&src[0]),
		C.size_t(len(src)),
	)

}
