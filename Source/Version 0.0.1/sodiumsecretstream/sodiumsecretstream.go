package sodiumsecretstream

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/secretstreaminitpushbox"
	"ASodium/secretstreampullbox"
	"ASodium/secretstreampushbox"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetABytesLength() int {
	return int(C.crypto_secretstream_xchacha20poly1305_abytes())
}

func GetKeyLength() int {
	return int(C.crypto_secretstream_xchacha20poly1305_keybytes())
}

func GetTagMessageByte() byte {
	return byte(C.crypto_secretstream_xchacha20poly1305_tag_message())
}

func GetTagPushByte() byte {
	return byte(C.crypto_secretstream_xchacha20poly1305_tag_push())
}

func GetTagRekeyByte() byte {
	return byte(C.crypto_secretstream_xchacha20poly1305_tag_rekey())
}

func GetTagFinalByte() byte {
	return byte(C.crypto_secretstream_xchacha20poly1305_tag_final())
}

func GetMessageBytesMaxLength() uint64 {
	return uint64(C.crypto_secretstream_xchacha20poly1305_messagebytes_max())
}

func GetStateBytesLength() int {
	return int(C.crypto_secretstream_xchacha20poly1305_statebytes())
}

func GetHeaderBytesLength() int {
	return int(C.crypto_secretstream_xchacha20poly1305_headerbytes())
}

func KeyGen() []byte {
	key := make([]byte, GetKeyLength())
	C.crypto_secretstream_xchacha20poly1305_keygen(
		(*C.uchar)(&key[0]),
	)
	return key
}

func KeyIntPtrGen() unsafe.Pointer {
	keyPtr, isZero := sodiumguardedheapallocation.SodiumMalloc(GetKeyLength())

	if !isZero {
		C.crypto_secretstream_xchacha20poly1305_keygen(
			(*C.uchar)(keyPtr),
		)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(keyPtr)
	} else {
		keyPtr = nil
	}
	return keyPtr
}

func SecretStreamInitPush(key []byte, clearKey bool) (*secretstreaminitpushbox.SecretStreamInitPushBox, error) {
	state := make([]byte, GetStateBytesLength())
	header := make([]byte, GetHeaderBytesLength())

	ret := C.crypto_secretstream_xchacha20poly1305_init_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(&header[0]),
		(*C.uchar)(&key[0]),
	)

	if ret != 0 {
		return nil, errors.New("failed to create SecretStreamInitPushBox")
	}

	if clearKey {
		sodiumsecurememory.MemZero(key)
	}

	return &secretstreaminitpushbox.SecretStreamInitPushBox{
		StateByte:  state,
		HeaderByte: header,
		StatePtr:   nil,
		HeaderPtr:  nil,
	}, nil
}

func SecretStreamInitPushPtr(key unsafe.Pointer, clearKey bool) (*secretstreaminitpushbox.SecretStreamInitPushBox, error) {

	state, isZeroState := sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())
	header, isZeroHeader := sodiumguardedheapallocation.SodiumMalloc(GetHeaderBytesLength())

	if isZeroState || isZeroHeader {
		return &secretstreaminitpushbox.SecretStreamInitPushBox{
			StateByte:  nil,
			HeaderByte: nil,
			StatePtr:   nil,
			HeaderPtr:  nil,
		}, nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

	ret := C.crypto_secretstream_xchacha20poly1305_init_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(header),
		(*C.uchar)(key),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

	if ret != 0 {
		return nil, errors.New("failed to create SecretStreamInitPushBox")
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return &secretstreaminitpushbox.SecretStreamInitPushBox{
		StateByte:  nil,
		HeaderByte: nil,
		StatePtr:   state,
		HeaderPtr:  header,
	}, nil
}

func SecretStreamPush(
	state []byte,
	message []byte,
	additionalData []byte,
	additionalDataLength uint64,
	tag byte,
	clearkey bool,
) (*secretstreampushbox.SecretStreamPushBox, error) {

	msgLen := uint64(len(message))
	if msgLen > GetMessageBytesMaxLength() {
		return nil, errors.New("message too large")
	}

	cipher := make([]byte, len(message)+GetABytesLength())

	ret := C.crypto_secretstream_xchacha20poly1305_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(&cipher[0]),
		nil,
		(*C.uchar)(&message[0]),
		C.ulonglong(msgLen),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		C.ulonglong(additionalDataLength),
		C.uchar(tag),
	)

	if clearkey {
		sodiumsecurememory.MemZero(state)
	}

	if ret != 0 {
		return nil, errors.New("failed to create SecretStreamPushBox")
	}

	return &secretstreampushbox.SecretStreamPushBox{
		StateByte:        state,
		MessageByte:      message,
		AdditionalData:   additionalData,
		CipherText:       cipher,
		CipherTextLength: int64(len(cipher)),
	}, nil
}

func SecretStreamPushPtr(
	state unsafe.Pointer,
	message []byte,
	additionalData []byte,
	additionalDataLength uint64,
	tag byte,
	clearState bool,
) (*secretstreampushbox.SecretStreamPushBox, error) {

	msgLen := uint64(len(message))
	if msgLen > GetMessageBytesMaxLength() {
		return nil, errors.New("message too large")
	}

	cipher := make([]byte, len(message)+GetABytesLength())

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)

	ret := C.crypto_secretstream_xchacha20poly1305_push(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(&cipher[0]),
		nil,
		(*C.uchar)(&message[0]),
		C.ulonglong(msgLen),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		C.ulonglong(additionalDataLength),
		C.uchar(tag),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if ret != 0 {
		return nil, errors.New("failed to create SecretStreamPushBox")
	}

	if clearState {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
		sodiumguardedheapallocation.SodiumFree(state)
	}

	return &secretstreampushbox.SecretStreamPushBox{
		StatePtr:         state,
		MessageByte:      message,
		AdditionalData:   additionalData,
		CipherText:       cipher,
		CipherTextLength: int64(len(cipher)),
	}, nil
}

func SecretStreamInitPull(
	header []byte,
	key []byte,
	clearKey bool,
) ([]byte, error) {

	if len(header) != GetHeaderBytesLength() {
		return nil, errors.New("invalid header length")
	}
	if len(key) != GetKeyLength() {
		return nil, errors.New("invalid key length")
	}

	state := make([]byte, GetStateBytesLength())

	ret := C.crypto_secretstream_xchacha20poly1305_init_pull(
		(*C.crypto_secretstream_xchacha20poly1305_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&header[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)

	if ret == -1 {
		return nil, errors.New("header is invalid")
	}

	if clearKey {
		sodiumsecurememory.MemZero(header)
		sodiumsecurememory.MemZero(key)
	}

	return state, nil
}

func SecretStreamInitPullPtr(
	header unsafe.Pointer,
	key unsafe.Pointer,
	clearKey bool,
) (unsafe.Pointer, error) {

	if header == nil || key == nil {
		return nil, errors.New("header or key is nil")
	}

	state, isZero := sodiumguardedheapallocation.SodiumMalloc(GetStateBytesLength())

	if !isZero {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(header)
		sodiumguardedheapallocation.SodiumMProtectReadOnly(key)

		ret := C.crypto_secretstream_xchacha20poly1305_init_pull(
			(*C.crypto_secretstream_xchacha20poly1305_state)(state),
			(*C.uchar)(header),
			(*C.uchar)(key),
		)

		sodiumguardedheapallocation.SodiumMProtectNoAccess(header)
		sodiumguardedheapallocation.SodiumMProtectNoAccess(key)

		if ret == -1 {
			return nil, errors.New("header is invalid")
		}
	} else {
		state = nil
	}

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(header)
		sodiumguardedheapallocation.SodiumMProtectReadWrite(key)
		sodiumguardedheapallocation.SodiumFree(header)
		sodiumguardedheapallocation.SodiumFree(key)
	}

	return state, nil
}

func SecretStreamPull(
	state []byte,
	tag byte,
	ciphertext []byte,
	additionalData []byte,
	additionalDataLen int64,
	clearkey bool,
) (*secretstreampullbox.SecretStreamPullBox, error) {

	if len(ciphertext) < GetABytesLength() {
		return nil, errors.New("ciphertext too short")
	}

	message := make([]byte, len(ciphertext)-GetABytesLength())
	var messageLen C.ulonglong
	tagOut := C.uchar(tag)

	ret := C.crypto_secretstream_xchacha20poly1305_pull(
		(*C.crypto_secretstream_xchacha20poly1305_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		&messageLen,
		&tagOut,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.ulonglong(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		C.ulonglong(additionalDataLen),
	)

	if clearkey {
		sodiumsecurememory.MemZero(state)
	}

	if ret == -1 {
		return nil, errors.New("Unable to do pull operations")
	}

	box := &secretstreampullbox.SecretStreamPullBox{
		StateByte:      state,
		MessageByte:    message,
		MessageLength:  int64(len(message)),
		CipherText:     ciphertext,
		AdditionalData: additionalData,
		TagByte:        byte(tagOut),
	}

	return box, nil
}

func SecretStreamPullPtr(
	state unsafe.Pointer,
	tag byte,
	ciphertext []byte,
	additionalData []byte,
	additionalDataLen int64,
	clearkey bool,
) (*secretstreampullbox.SecretStreamPullBox, error) {

	if state == nil {
		return nil, errors.New("state pointer is nil")
	}

	message := make([]byte, len(ciphertext)-GetABytesLength())
	var messageLen C.ulonglong
	tagOut := C.uchar(tag)

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)

	ret := C.crypto_secretstream_xchacha20poly1305_pull(
		(*C.crypto_secretstream_xchacha20poly1305_state)(state),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		&messageLen,
		&tagOut,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.ulonglong(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])),
		C.ulonglong(additionalDataLen),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(state)

	if ret == -1 {
		return nil, errors.New("Unable to do pull operations")
	}

	box := &secretstreampullbox.SecretStreamPullBox{
		StatePtr:       state,
		MessageByte:    message,
		MessageLength:  int64(len(message)),
		CipherText:     ciphertext,
		AdditionalData: additionalData,
		TagByte:        byte(tagOut),
	}

	return box, nil
}

func SecretStreamReKey(state []byte) []byte {
	C.crypto_secretstream_xchacha20poly1305_rekey(
		(*C.crypto_secretstream_xchacha20poly1305_state)(unsafe.Pointer(&state[0])),
	)
	return state
}

func SecretStreamReKeyPtr(state unsafe.Pointer) (unsafe.Pointer, error) {
	if state == nil {
		return nil, errors.New("state must not be nil")
	}

	sodiumguardedheapallocation.SodiumMProtectReadWrite(state)
	C.crypto_secretstream_xchacha20poly1305_rekey((*C.crypto_secretstream_xchacha20poly1305_state)(state))

	return state, nil
}
