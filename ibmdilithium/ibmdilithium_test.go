package ibmdilithium

import (
	"crypto"
	"fmt"
	"testing"

	grep11 "github.com/IBM-Cloud/hpcs-grep11-go/grpc"
)

func TestDilithium(t *testing.T) {

	var err error

	npriv, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	}

	b, err := MarshalPkcs8Pem(npriv)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Sprintln(string(b))
	}
	npriv2, err := UnmarshalPkcs8Pem(b)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Sprintln(len(npriv2.PublicKey.Bytes))
	}
	var sresp *grep11.SignResponse

	sresp, err = SignDilith(npriv2.Bytes, []byte("Dupa Jasio"), crypto.SHA256)
	if err != nil {
		t.Error(err)
	}
	_, err = VerifyDilithiumSignature(npriv.PublicKey.Bytes, []byte("Dupa Jasio"), sresp.Signature, crypto.SHA256)
	fmt.Println("Verification error:", err)
	if err != nil {
		t.Error(err)
	}

}
