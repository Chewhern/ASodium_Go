package sodiumkeyexchange

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"
import (
	"ASodium/keypair"
	"ASodium/revampedkeypair"
	"ASodium/sodiumguardedheapallocation"
	"ASodium/sodiumkeyexchangesharedsecretbox"
	"ASodium/sodiumkeyexchangesharedsecretpointerbox"
	"ASodium/sodiumsecurememory"
	"errors"
	"unsafe"
)

func GetPublicKeyBytesLength() int {
	return int(C.crypto_kx_publickeybytes())
}

func GetSecretKeyBytesLength() int {
	return int(C.crypto_kx_secretkeybytes())
}

func GetSeedBytesLength() int {
	return int(C.crypto_kx_seedbytes())
}

func GetSessionKeyBytesLength() int {
	return int(C.crypto_kx_sessionkeybytes())
}

func GenerateRevampedKeyPair() (*revampedkeypair.RevampedKeyPair, error) {
	pk := make([]byte, GetPublicKeyBytesLength())
	sk := make([]byte, GetSecretKeyBytesLength())

	ret := C.crypto_kx_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
	)

	if ret != 0 {
		return nil, errors.New("failed to create key exchange key pair")
	}
	var myerror error
	var mykeypair *revampedkeypair.RevampedKeyPair
	mykeypair, myerror = revampedkeypair.NewRevampedKeyPair(pk, sk)

	return mykeypair, myerror
}

func GenerateKeyPair() (*keypair.KeyPair, error) {
	pkLen := GetPublicKeyBytesLength()
	skLen := GetSecretKeyBytesLength()

	var pk, sk unsafe.Pointer
	var isZero1, isZero2 bool
	pk, isZero1 = sodiumguardedheapallocation.SodiumMalloc(pkLen)
	if isZero1 == true {
		return nil, errors.New("failed to allocate public key")
	}

	sk, isZero2 = sodiumguardedheapallocation.SodiumMalloc(skLen)
	if isZero2 == true {
		sodiumguardedheapallocation.SodiumFree(pk)
		return nil, errors.New("failed to allocate secret key")
	}

	ret := C.crypto_kx_keypair(
		(*C.uchar)(pk),
		(*C.uchar)(sk),
	)

	if ret != 0 {
		sodiumguardedheapallocation.SodiumFree(pk)
		sodiumguardedheapallocation.SodiumFree(sk)
		return nil, errors.New("failed to create key exchange key pair")
	}

	// Protect secret key
	sodiumguardedheapallocation.SodiumMProtectNoAccess(sk)

	var myKeyPair *keypair.KeyPair
	myKeyPair = keypair.NewKeyPair(sk, skLen, pk, pkLen)

	return myKeyPair, nil
}

func GenerateSeededRevampedKeyPair(seed []byte, clearSeed bool) (*revampedkeypair.RevampedKeyPair, error) {
	if seed == nil {
		return nil, errors.New("seed must not be nil")
	}
	if len(seed) != GetSeedBytesLength() {
		return nil, errors.New("seed length is invalid")
	}

	pk := make([]byte, GetPublicKeyBytesLength())
	sk := make([]byte, GetSecretKeyBytesLength())

	ret := C.crypto_kx_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]),
	)

	if ret != 0 {
		return nil, errors.New("failed to create seeded key pair")
	}

	if clearSeed {
		sodiumsecurememory.MemZero(seed)
	}

	var myerror error
	var mykeypair *revampedkeypair.RevampedKeyPair
	mykeypair, myerror = revampedkeypair.NewRevampedKeyPair(pk, sk)

	return mykeypair, myerror
}

func GenerateSeededKeyPair(seed unsafe.Pointer, clearKey bool) (*keypair.KeyPair, error) {
	if seed == nil {
		return nil, errors.New("seed must not be null")
	}

	var pk, sk unsafe.Pointer
	isZero1 := true
	pk, isZero1 = sodiumguardedheapallocation.SodiumMalloc(GetPublicKeyBytesLength())

	isZero2 := true
	sk, isZero2 = sodiumguardedheapallocation.SodiumMalloc(GetSecretKeyBytesLength())

	if isZero1 == true && isZero2 == true {
		return nil, errors.New("Unable to create pointers for these variables..")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(seed)

	ret := C.crypto_kx_seed_keypair(
		(*C.uchar)(pk),
		(*C.uchar)(sk),
		(*C.uchar)(seed),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(seed)

	if ret != 0 {
		return nil, errors.New("failed to create seeded key pair")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(sk)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(seed)
		sodiumguardedheapallocation.SodiumFree(seed)
	}

	var myKeyPair *keypair.KeyPair
	myKeyPair = keypair.NewKeyPair(sk, GetSecretKeyBytesLength(), pk, GetPublicKeyBytesLength())

	return myKeyPair, nil
}

func CalculateClientSharedSecret(
	clientPK, clientSK, serverPK []byte,
	clearKey bool,
) (*sodiumkeyexchangesharedsecretbox.SodiumKeyExchangeSharedSecretBox, error) {

	if len(clientPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid client public key length")
	}
	if len(clientSK) != GetSecretKeyBytesLength() {
		return nil, errors.New("invalid client secret key length")
	}
	if len(serverPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid server public key length")
	}

	rx := make([]byte, GetSessionKeyBytesLength())
	tx := make([]byte, GetSessionKeyBytesLength())

	ret := C.crypto_kx_client_session_keys(
		(*C.uchar)(unsafe.Pointer(&rx[0])),
		(*C.uchar)(unsafe.Pointer(&tx[0])),
		(*C.uchar)(unsafe.Pointer(&clientPK[0])),
		(*C.uchar)(unsafe.Pointer(&clientSK[0])),
		(*C.uchar)(unsafe.Pointer(&serverPK[0])),
	)

	if ret != 0 {
		return nil, errors.New("failed to calculate shared secret")
	}

	if clearKey {
		sodiumsecurememory.MemZero(clientSK)
	}

	return &sodiumkeyexchangesharedsecretbox.SodiumKeyExchangeSharedSecretBox{
		ReadSharedSecret:     rx,
		TransferSharedSecret: tx,
	}, nil
}

func CalculateServerSharedSecret(
	serverPK []byte,
	serverSK []byte,
	clientPK []byte,
	clearKey bool,
) (*sodiumkeyexchangesharedsecretbox.SodiumKeyExchangeSharedSecretBox, error) {

	if len(serverPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid server public key length")
	}
	if len(serverSK) != GetSecretKeyBytesLength() {
		return nil, errors.New("invalid server secret key length")
	}
	if len(clientPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid client public key length")
	}

	readSS := make([]byte, GetSessionKeyBytesLength())
	writeSS := make([]byte, GetSessionKeyBytesLength())

	ret := C.crypto_kx_server_session_keys(
		(*C.uchar)(&readSS[0]),
		(*C.uchar)(&writeSS[0]),
		(*C.uchar)(&serverPK[0]),
		(*C.uchar)(&serverSK[0]),
		(*C.uchar)(&clientPK[0]),
	)

	if ret != 0 {
		return nil, errors.New("failed to calculate server shared secret")
	}

	if clearKey {
		sodiumsecurememory.MemZero(serverSK)
	}

	return &sodiumkeyexchangesharedsecretbox.SodiumKeyExchangeSharedSecretBox{
		ReadSharedSecret:     readSS,
		TransferSharedSecret: writeSS,
	}, nil
}

func CalculateClientSharedSecretPtr(
	clientPK []byte,
	clientSK unsafe.Pointer,
	serverPK []byte,
	clearKey bool,
) (*sodiumkeyexchangesharedsecretpointerbox.SodiumKeyExchangeSharedSecretPointerBox, error) {

	if len(clientPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid client public key length")
	}
	if clientSK == nil {
		return nil, errors.New("client secret key pointer is nil")
	}
	if len(serverPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid server public key length")
	}

	readPtr, ok1 := sodiumguardedheapallocation.SodiumMalloc(GetSessionKeyBytesLength())
	writePtr, ok2 := sodiumguardedheapallocation.SodiumMalloc(GetSessionKeyBytesLength())

	if ok1 == true || ok2 == true {
		return nil, errors.New("Unable to create shared secret box")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(clientSK)

	ret := C.crypto_kx_client_session_keys(
		(*C.uchar)(readPtr),
		(*C.uchar)(writePtr),
		(*C.uchar)(&clientPK[0]),
		(*C.uchar)(clientSK),
		(*C.uchar)(&serverPK[0]),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(clientSK)

	if ret != 0 {
		return nil, errors.New("failed to calculate client shared secret")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(readPtr)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(writePtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(clientSK)
		sodiumguardedheapallocation.SodiumFree(clientSK)
	}

	return &sodiumkeyexchangesharedsecretpointerbox.SodiumKeyExchangeSharedSecretPointerBox{
		ReadSharedSecret:           readPtr,
		ReadSharedSecretLength:     GetSessionKeyBytesLength(),
		TransferSharedSecret:       writePtr,
		TransferSharedSecretLength: GetSessionKeyBytesLength(),
	}, nil
}

func CalculateServerSharedSecretPtr(
	serverPK []byte,
	serverSK unsafe.Pointer,
	clientPK []byte,
	clearKey bool,
) (*sodiumkeyexchangesharedsecretpointerbox.SodiumKeyExchangeSharedSecretPointerBox, error) {

	if len(serverPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid server public key length")
	}
	if serverSK == nil {
		return nil, errors.New("server secret key pointer is nil")
	}
	if len(clientPK) != GetPublicKeyBytesLength() {
		return nil, errors.New("invalid client public key length")
	}

	readPtr, ok1 := sodiumguardedheapallocation.SodiumMalloc(GetSessionKeyBytesLength())
	writePtr, ok2 := sodiumguardedheapallocation.SodiumMalloc(GetSessionKeyBytesLength())

	if ok1 == true || ok2 == true {
		return nil, errors.New("Unable to create shared secret box")
	}

	sodiumguardedheapallocation.SodiumMProtectReadOnly(serverSK)

	ret := C.crypto_kx_server_session_keys(
		(*C.uchar)(readPtr),
		(*C.uchar)(writePtr),
		(*C.uchar)(&serverPK[0]),
		(*C.uchar)(serverSK),
		(*C.uchar)(&clientPK[0]),
	)

	sodiumguardedheapallocation.SodiumMProtectNoAccess(serverSK)

	if ret != 0 {
		return nil, errors.New("failed to calculate server shared secret")
	}

	sodiumguardedheapallocation.SodiumMProtectNoAccess(readPtr)
	sodiumguardedheapallocation.SodiumMProtectNoAccess(writePtr)

	if clearKey {
		sodiumguardedheapallocation.SodiumMProtectReadWrite(serverSK)
		sodiumguardedheapallocation.SodiumFree(serverSK)
	}

	return &sodiumkeyexchangesharedsecretpointerbox.SodiumKeyExchangeSharedSecretPointerBox{
		ReadSharedSecret:           readPtr,
		ReadSharedSecretLength:     GetSessionKeyBytesLength(),
		TransferSharedSecret:       writePtr,
		TransferSharedSecretLength: GetSessionKeyBytesLength(),
	}, nil
}
