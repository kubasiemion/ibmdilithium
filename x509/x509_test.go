package x509

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/kubasiemion/ibmdilithium/ibmdilithium"
)

func TestX509RSA4DIL(t *testing.T) {

	block, _ := pem.Decode([]byte(selfSignedRootCertRSA4096Pem))
	RootCert, e := ParseCertificate(block.Bytes)
	if e != nil {
		t.Error(e)
		return
	}
	//fmt.Println(hex.EncodeToString(block.Bytes))

	ca := GetTemplate()

	pub := ibmdilithium.TestPubKey()
	fmt.Println(len(pub.Bytes))

	block, _ = pem.Decode([]byte(rsa4096privPem))
	rootRSAKey, e := ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Error(e)
		return
	}
	certb, e := CreateCertificate(rand.Reader, ca, RootCert, pub, rootRSAKey)
	if e != nil {
		t.Error(e)
		return
	}

	block = &pem.Block{Type: "CERTIFICATE", Bytes: certb}
	certbuf := new(bytes.Buffer)
	e = pem.Encode(certbuf, block)
	if e != nil {
		t.Error(e)
		return
	}
	//fmt.Println(string(certbuf.Bytes()))

	p2, e := ParseCertificate(certb)
	if e != nil {
		t.Error(e)
		return
	}
	cpool := NewCertPool()
	cpool.AddCert(RootCert)
	chain, err := p2.Verify(VerifyOptions{Roots: cpool})
	fmt.Println(err, chain)
}

//This test assumes grep11 available
func TestX509DIL4RSA(t *testing.T) {
	block, _ := pem.Decode([]byte(rsa4096privPem))
	rootRSAKey, e := ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Error(e)
		return
	}
	block, _ = pem.Decode([]byte(selfSignedRootCertRSA4096Pem))
	RootCert, e := ParseCertificate(block.Bytes)
	if e != nil {
		t.Error(e)
		return
	}

	cpool := NewCertPool()
	cpool.AddCert(RootCert)

	block, _ = pem.Decode([]byte(RSA4DILCertPem))
	p2, e := parseCertificate(block.Bytes)

	xc, e := CreateCertificate(rand.Reader, GetTemplate(), p2, &rootRSAKey.(*rsa.PrivateKey).PublicKey, ibmdilithium.TestPrivKey())
	if e != nil {
		fmt.Println(e)
		return
	}

	p3, e := ParseCertificate(xc)
	if e != nil {
		t.Error(e)
		return
	}
	interm := NewCertPool()
	interm.AddCert(p2)
	fmt.Println(p3.Verify(VerifyOptions{Roots: cpool, Intermediates: interm}))
}
