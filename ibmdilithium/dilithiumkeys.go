package ibmdilithium

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
)

var SHAKE256WithDilithiumOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}

type DILPublicKey struct {
	OID   asn1.ObjectIdentifier
	Bytes []byte
}

func PrivKeyFromBytes(privb, pub []byte) (*DILPrivateKey, error) {
	if l := len(privb); l != 5808 {
		return nil, fmt.Errorf("%v privkey bytes given, expected 5808", l)
	}
	priv := new(DILPrivateKey)
	priv.OID = OIDDilithiumHigh
	priv.Bytes = privb
	priv.PublicKey = &DILPublicKey{OID: priv.OID, Bytes: pub}
	return priv, nil

}

type DILPrivateKey struct {
	OID       asn1.ObjectIdentifier
	Bytes     []byte
	PublicKey *DILPublicKey
}

func (dilp *DILPublicKey) Verify(signed, signature []byte) error {
	_, e := VerifyDilithiumSignature(dilp.Bytes, signed, signature, crypto.SHA256)
	return e
}

//From crypto.Signer
func (dil *DILPrivateKey) Public() crypto.PublicKey {
	return dil.PublicKey
}

//From crypto.Signer
func (dil *DILPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var hash crypto.Hash
	if opts == nil || opts.HashFunc() == 0 {
		hash = crypto.SHA256
	} else {
		hash = opts.HashFunc()
	}

	sigres, err := SignDilith(dil.Bytes, digest, hash)
	var sigb []byte
	if sigres != nil {
		sigb = sigres.Signature
	}
	return sigb, err
}

//from x509.privKey
func (dil *DILPublicKey) Equal(pub crypto.PublicKey) bool {
	if dilpub, ok := pub.(*DILPublicKey); !ok {
		return ok
	} else {
		return bytes.Equal(dil.Bytes, dilpub.Bytes)
	}

}

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// CMS-style Attribute is SEQUENCE { attrType OBJECT IDENTIFIER, attrValue SET OF ANY --DEFINED BY type-- }
	Attribute0 []byte `asn1:"optional,tag:0"`
	Attribute1 []byte `asn1:"optional,tag:1"`
}

func MarshalPkcs8Pem(dil *DILPrivateKey) ([]byte, error) {
	p8 := pkcs8{}
	p8.PrivateKey = dil.Bytes
	p8.Attribute0 = dil.PublicKey.Bytes
	p8.Version = 1
	p8.Algo = pkix.AlgorithmIdentifier{Algorithm: dil.OID}
	b, err := asn1.Marshal(p8)
	if err != nil {
		return nil, err
	}
	bl := pem.Block{}
	bl.Type = "DILITHIUM PRIVATE KEY"
	bl.Bytes = b
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &bl)
	return buf.Bytes(), err
}

//This assumes that the PublicKey bytes are stored as Attribute 0
func UnmarshalPkcs8Pem(pembytes []byte) (*DILPrivateKey, error) {
	bl, _ := pem.Decode(pembytes)
	p8 := new(pkcs8)
	_, err := asn1.Unmarshal(bl.Bytes, p8)
	if err != nil {
		return nil, err
	}
	if !p8.Algo.Algorithm.Equal(OIDDilithiumHigh) {
		return nil, fmt.Errorf("wrong OID: %s", p8.Algo.Algorithm)
	}
	return PrivKeyFromBytes(p8.PrivateKey, p8.Attribute0)
}
