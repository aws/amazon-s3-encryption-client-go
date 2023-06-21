package s3crypto

import (
	"strings"
	"testing"
)

func TestAESGCMContentCipherBuilderV2(t *testing.T) {
	builder := AESGCMContentCipherBuilderV2(mockGeneratorV2{})
	cipher, err := builder.ContentCipher()

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if cipher == nil {
		t.Errorf("expected non-nil vaue")
	}
}

func TestRegisterAESGCMContentCipher(t *testing.T) {
	cr := NewCryptoRegistry()
	err := RegisterAESGCMContentCipher(cr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if v, ok := cr.GetCEK("AES/GCM/NoPadding"); !ok {
		t.Fatal("expected cek handler to be registered")
	} else if v == nil {
		t.Fatal("expected non-nil cek handler")
	}

	if v, ok := cr.GetPadder("NoPadding"); !ok {
		t.Fatal("expected padder to be registered")
	} else if v != NoPadder {
		t.Fatal("padder did not match expected type")
	}

	err = RegisterAESGCMContentCipher(cr)
	if err == nil {
		t.Fatal("expected error, got none")
	} else if !strings.Contains(err.Error(), "duplicate cek registry entry") {
		t.Errorf("expected duplicate entry, got %v", err)
	}

	if _, ok := cr.RemoveCEK("AES/GCM/NoPadding"); !ok {
		t.Error("expected value to be removed")
	}
	err = RegisterAESGCMContentCipher(cr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if _, ok := cr.RemoveCEK("AES/GCM/NoPadding"); !ok {
		t.Fatalf("expected value to be removed")
	}
	if _, ok := cr.RemovePadder("NoPadding"); !ok {
		t.Fatalf("expected value to be removed")
	}
	if err := cr.AddPadder("NoPadding", mockPadder{}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	err = RegisterAESGCMContentCipher(cr)
	if err == nil {
		t.Fatalf("expected error, got %v", err)
	} else if !strings.Contains(err.Error(), "does not match expected type") {
		t.Errorf("expected padder type error, got %v", err)
	}
}

func TestAESGCMContentCipherBuilderV2_isAWSFixture(t *testing.T) {
	builder := AESGCMContentCipherBuilderV2(NewKMSContextKeyGenerator(&mockKMS{}, "cmk", nil))
	if !builder.(awsFixture).isAWSFixture() {
		t.Error("expected to be AWS ContentCipherBuilder constructed with a AWS CipherDataGenerator")
	}

	builder = AESGCMContentCipherBuilderV2(mockGeneratorV2{})
	if builder.(awsFixture).isAWSFixture() {
		t.Error("expected to return that this is not an AWS fixture")
	}
}
