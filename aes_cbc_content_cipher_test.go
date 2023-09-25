package s3crypto

import (
	"strings"
	"testing"
)

func TestRegisterAESCBCContentCipher(t *testing.T) {
	cr := NewCryptographicMaterialsManager()
	padder := AESCBCPadder
	err := RegisterAESCBCContentCipher(cr, padder)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if v, ok := cr.GetCEK("AES/CBC/PKCS5Padding"); !ok {
		t.Fatal("expected cek algorithm handler to registered")
	} else if v == nil {
		t.Fatal("expected non-nil cek handler to be registered")
	}

	if v, ok := cr.GetPadder("AES/CBC/PKCS5Padding"); !ok {
		t.Fatal("expected padder to be registered")
	} else if v != padder {
		t.Fatal("padder did not match provided value")
	}

	// try to register padder again
	err = RegisterAESCBCContentCipher(cr, padder)
	if err == nil {
		t.Fatal("expected error, got none")
	} else if !strings.Contains(err.Error(), "duplicate cek registry entry") {
		t.Errorf("expected duplicate cek entry, got %v", err)
	}

	// try to regster padder with cek removed but padder entry still present
	if _, ok := cr.RemoveCEK("AES/CBC/PKCS5Padding"); !ok {
		t.Fatalf("expected value to be removed")
	}
	err = RegisterAESCBCContentCipher(cr, padder)
	if err == nil {
		t.Fatal("expected error, got none")
	} else if !strings.Contains(err.Error(), "duplicate padder registry entry") {
		t.Errorf("expected duplicate padder entry, got %v", err)
	}
}
