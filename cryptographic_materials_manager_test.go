package s3crypto

import (
	"strings"
	"testing"
)

func TestCryptographicMaterialsManager_Keyring(t *testing.T) {
	cr := NewCryptographicMaterialsManager()

	mockKeyring := KeyringEntry(func(envelope Envelope) (CipherDataDecrypter, error) {
		return nil, nil
	})

	if _, ok := cr.GetKeyring("foo"); ok {
		t.Errorf("expected Keyring to not be present")
	}

	if _, ok := cr.RemoveKeyring("foo"); ok {
		t.Errorf("expected Keyring to not have been removed")
	}

	if err := cr.AddKeyring("foo", nil); err == nil {
		t.Errorf("expected error, got none")
	}

	if err := cr.AddKeyring("foo", mockKeyring); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if err := cr.AddKeyring("foo", mockKeyring); err == nil {
		t.Error("expected error, got none")
	}

	if v, ok := cr.GetKeyring("foo"); !ok || v == nil {
		t.Error("expected Keyring to be present and not nil")
	}

	if v, ok := cr.RemoveKeyring("foo"); !ok || v == nil {
		t.Error("expected Keyring to have been removed and not nil")
	}

	if _, ok := cr.GetKeyring("foo"); ok {
		t.Error("expected Keyring to have been removed and not nil")
	}
}

func TestCryptographicMaterialsManager_CEK(t *testing.T) {
	cr := NewCryptographicMaterialsManager()

	mockEntry := CEKEntry(func(data CipherData) (ContentCipher, error) {
		return nil, nil
	})

	if _, ok := cr.GetCEK("foo"); ok {
		t.Errorf("expected Keyring to not be present")
	}

	if _, ok := cr.RemoveCEK("foo"); ok {
		t.Errorf("expected Keyring to not have been removed")
	}

	if err := cr.AddCEK("foo", nil); err == nil {
		t.Errorf("expected error, got none")
	}

	if err := cr.AddCEK("foo", mockEntry); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if err := cr.AddCEK("foo", mockEntry); err == nil {
		t.Error("expected error, got none")
	}

	if v, ok := cr.GetCEK("foo"); !ok || v == nil {
		t.Error("expected Keyring to be present and not nil")
	}

	if v, ok := cr.RemoveCEK("foo"); !ok || v == nil {
		t.Error("expected Keyring to have been removed and not nil")
	}

	if _, ok := cr.GetCEK("foo"); ok {
		t.Error("expected Keyring to have been removed and not nil")
	}
}

func TestCryptographicMaterialsManager_Padder(t *testing.T) {
	cr := NewCryptographicMaterialsManager()

	padder := &mockPadder{}

	if _, ok := cr.GetPadder("foo"); ok {
		t.Errorf("expected Keyring to not be present")
	}

	if _, ok := cr.RemovePadder("foo"); ok {
		t.Errorf("expected Keyring to not have been removed")
	}

	if err := cr.AddPadder("foo", nil); err == nil {
		t.Errorf("expected error, got none")
	}

	if err := cr.AddPadder("foo", padder); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if err := cr.AddPadder("foo", padder); err == nil {
		t.Error("expected error, got none")
	}

	if v, ok := cr.GetPadder("foo"); !ok || v == nil {
		t.Error("expected Keyring to be present and not nil")
	}

	if v, ok := cr.RemovePadder("foo"); !ok || v == nil {
		t.Error("expected Keyring to have been removed and not nil")
	}
}

func TestCryptographicMaterialsManager_valid(t *testing.T) {
	cr := NewCryptographicMaterialsManager()

	if err := cr.valid(); err == nil {
		t.Errorf("expected error, got none")
	} else if e, a := "at least one key Keyring algorithms must be provided", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected %v, got %v", e, a)
	}

	if err := cr.AddKeyring("foo", func(envelope Envelope) (CipherDataDecrypter, error) {
		return nil, nil
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := cr.valid(); err == nil {
		t.Fatalf("expected error, got none")
	} else if e, a := "least one content decryption algorithms must be provided", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected %v, got %v", e, a)
	}

	if err := cr.AddCEK("foo", func(data CipherData) (ContentCipher, error) {
		return nil, nil
	}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := cr.valid(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
