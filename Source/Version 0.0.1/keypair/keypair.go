package keypair

// #include <string.h>
import "C"

import (
	"ASodium/sodiumguardedheapallocation"
	"unsafe"
)

// KeyPair represents a cryptographic key pair in guarded memory
type KeyPair struct {
	PrivateKey       unsafe.Pointer
	PrivateKeyLength int
	PublicKey        unsafe.Pointer
	PublicKeyLength  int
}

// NewKeyPairEmpty creates an empty KeyPair
func NewKeyPairEmpty() *KeyPair {
	return &KeyPair{
		PrivateKey:       nil,
		PrivateKeyLength: 0,
		PublicKey:        nil,
		PublicKeyLength:  0,
	}
}

// NewKeyPair allocates a KeyPair with existing pointers
func NewKeyPair(privateKey unsafe.Pointer, privateLen int, publicKey unsafe.Pointer, publicLen int) *KeyPair {
	return &KeyPair{
		PrivateKey:       privateKey,
		PrivateKeyLength: privateLen,
		PublicKey:        publicKey,
		PublicKeyLength:  publicLen,
	}
}

// GetPrivateKey sets private key to read-only and returns pointer
func (kp *KeyPair) GetPrivateKey() unsafe.Pointer {
	if kp.PrivateKey != nil {
		sodiumguardedheapallocation.SodiumMProtectReadOnly(kp.PrivateKey)
	}
	return kp.PrivateKey
}

// ProtectPrivateKey sets private key to no access
func (kp *KeyPair) ProtectPrivateKey() {
	if kp.PrivateKey != nil {
		sodiumguardedheapallocation.SodiumMProtectNoAccess(kp.PrivateKey)
	}
}

// GetPrivateKeyLength returns private key length
func (kp *KeyPair) GetPrivateKeyLength() int {
	return kp.PrivateKeyLength
}

// GetPublicKey copies the public key to a Go slice
func (kp *KeyPair) GetPublicKey() []byte {
	if kp.PublicKey == nil || kp.PublicKeyLength == 0 {
		return nil
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(kp.PublicKey)

	buf := make([]byte, kp.PublicKeyLength)
	C.memcpy(unsafe.Pointer(&buf[0]), kp.PublicKey, C.size_t(kp.PublicKeyLength))

	sodiumguardedheapallocation.SodiumMProtectNoAccess(kp.PublicKey)

	return buf
}

// GetPublicKeyLength returns public key length
func (kp *KeyPair) GetPublicKeyLength() int {
	return kp.PublicKeyLength
}

// Clear frees both keys and zeroes memory
func (kp *KeyPair) Clear() {
	if kp.PrivateKey != nil {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(kp.PrivateKey)
		sodiumguardedheapallocation.SodiumFree(kp.PrivateKey)
		kp.PrivateKey = nil
		kp.PrivateKeyLength = 0
	}

	if kp.PublicKey != nil {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(kp.PublicKey)
		sodiumguardedheapallocation.SodiumFree(kp.PublicKey)
		kp.PublicKey = nil
		kp.PublicKeyLength = 0
	}
}
