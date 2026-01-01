package detachedbox

// DetachedBox represents a detached encryption box (ciphertext + MAC)
type DetachedBox struct {
	CipherText []byte
	Mac        []byte
	MACLength  int64
}

// NewDetachedBoxEmpty creates an empty DetachedBox
func NewDetachedBoxEmpty() *DetachedBox {
	return &DetachedBox{}
}

// NewDetachedBox creates a DetachedBox with ciphertext and MAC
func NewDetachedBox(cipherText, mac []byte) *DetachedBox {
	return &DetachedBox{
		CipherText: cipherText,
		Mac:        mac,
		MACLength:  int64(len(mac)),
	}
}
