package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"

	"github.com/kubasiemion/ibmdilithium/x509/pkix"

	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/kubasiemion/ibmdilithium/ibmdilithium"
	"github.com/kubasiemion/ibmdilithium/x509"
)

func main() {

	cryptoClient := ibmdilithium.CryptoClient()
	fmt.Println(cryptoClient)
	resp, err := ibmdilithium.GenerateKeyPair()
	if err != nil {
		fmt.Println(err)
	} else {
		npriv, _ := ibmdilithium.PrivKeyFromBytes(resp.PrivKeyBytes, resp.PubKeyBytes)
		b, err := ibmdilithium.MarshalPkcs8Pem(npriv)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(string(b))
		}
		npriv2, err := ibmdilithium.UnmarshalPkcs8Pem(b)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(len(npriv2.PublicKey.Bytes))
		}
		sresp, _ := ibmdilithium.SignDilith(npriv2.Bytes, []byte("Dupa Jasio"), crypto.SHA256)
		_, err = ibmdilithium.VerifyDilithiumSignature(npriv.PublicKey.Bytes, []byte("Dupa Jasio"), sresp.Signature, crypto.SHA256)
		fmt.Println("Verification:", err)
	}

	b, e := os.ReadFile("selfSignedRSA4096cert.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	block, _ := pem.Decode(b)
	parent, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}
	//fmt.Println(hex.EncodeToString(block.Bytes))

	ca := getTemplate()

	pub := ibmdilithium.TestPubKey()
	fmt.Println(len(pub.Bytes))

	prpem, e := os.ReadFile("aaaRSA4096key.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	block, _ = pem.Decode(prpem)
	prkey, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		fmt.Println(e)
		return
	}
	certb, e := x509.CreateCertificate(rand.Reader, ca, parent, pub, prkey)
	if e != nil {
		fmt.Println(e)
		return
	}
	//fmt.Println(hex.EncodeToString(certb))
	fmt.Println(len(certb))
	block = &pem.Block{Type: "CERTIFICATE", Bytes: certb}
	certbuf := new(bytes.Buffer)
	e = pem.Encode(certbuf, block)
	if e != nil {
		fmt.Println(e)
		return
	}
	//fmt.Println(string(certbuf.Bytes()))

	p2, e := x509.ParseCertificate(certb)
	if e != nil {
		fmt.Println(e)
		return
	}
	cpool := x509.NewCertPool()
	cpool.AddCert(parent)
	chain, err := p2.Verify(x509.VerifyOptions{Roots: cpool})
	fmt.Println(err, chain)

	xc, e := x509.CreateCertificate(rand.Reader, ca, p2, &prkey.(*rsa.PrivateKey).PublicKey, ibmdilithium.TestPrivKey())
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(len(xc))
	p3, e := x509.ParseCertificate(xc)
	fmt.Println(e)
	interm := x509.NewCertPool()
	interm.AddCert(p2)
	fmt.Println(p3.Verify(x509.VerifyOptions{Roots: cpool, Intermediates: interm}))
}

func getTemplate() *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"SANTALAB"},
			Country:       []string{"ES"},
			Province:      []string{""},
			Locality:      []string{"Madrid"},
			StreetAddress: []string{"Santa Campus"},
			PostalCode:    []string{"28266"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return ca
}
