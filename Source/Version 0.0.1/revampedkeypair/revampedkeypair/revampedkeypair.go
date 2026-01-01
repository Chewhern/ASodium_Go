package revampedkeypair

import (
	"ASodium/sodiumsecurememory"
	"fmt"
	"runtime"
)

// RevampedKeyPair holds public and private keys in Go-managed memory
type RevampedKeyPair struct {
	publicKey  []byte
	privateKey []byte
}

// NewRevampedKeyPair initializes a new RevampedKeyPair
func NewRevampedKeyPair(publicKey, privateKey []byte) (*RevampedKeyPair, error) {
	// Verify private key length is a multiple of 16
	if len(privateKey)%16 != 0 {
		return nil, fmt.Errorf("private key length must be a multiple of 16 bytes")
	}

	kp := &RevampedKeyPair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	// Register a finalizer (rough equivalent of C# destructor)
	runtime.SetFinalizer(kp, func(k *RevampedKeyPair) {
		k.Clear()
	})

	return kp, nil
}

// PublicKey returns the public key
func (k *RevampedKeyPair) PublicKey() []byte {
	return k.publicKey
}

// PrivateKey returns the private key
func (k *RevampedKeyPair) PrivateKey() []byte {
	return k.privateKey
}

// Clear securely zeroes both public and private keys
func (k *RevampedKeyPair) Clear() {
	if k.privateKey != nil {
		sodiumsecurememory.MemZero(k.privateKey)
	}
	if k.publicKey != nil {
		sodiumsecurememory.MemZero(k.publicKey)
	}
}
