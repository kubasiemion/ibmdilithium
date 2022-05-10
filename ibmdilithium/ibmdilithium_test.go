package ibmdilithium

import (
	"crypto"
	"fmt"
	"testing"
)

func TestDilithium(t *testing.T) {

	resp, err := GenerateKeyPair()
	if err != nil {
		t.Error(err)
	} else {
		npriv, _ := PrivKeyFromBytes(resp.PrivKeyBytes, resp.PubKeyBytes)
		b, err := MarshalPkcs8Pem(npriv)
		if err != nil {
			t.Error(err)
		} else {
			fmt.Println(string(b))
		}
		npriv2, err := UnmarshalPkcs8Pem(b)
		if err != nil {
			t.Error(err)
		} else {
			fmt.Println(len(npriv2.PublicKey.Bytes))
		}
		sresp, _ := SignDilith(npriv2.Bytes, []byte("Dupa Jasio"), crypto.SHA256)
		_, err = VerifyDilithiumSignature(npriv.PublicKey.Bytes, []byte("Dupa Jasio"), sresp.Signature, crypto.SHA256)
		fmt.Println("Verification:", err)
		if err != nil {
			t.Error(err)
		}
	}
}
