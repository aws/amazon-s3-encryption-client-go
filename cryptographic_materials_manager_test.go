package s3crypto

// TODO: These are mildly helpful unit tests, rewrite against new CMM
//func TestCryptographicMaterialsManager_Keyring(t *testing.T) {
//	cr := NewCryptographicMaterialsManager()
//
//	mockKeyring := KeyringEntry(func(envelope ObjectMetadata) (CipherDataDecrypter, error) {
//		return nil, nil
//	})
//
//	if _, ok := cr.GetKeyring("foo"); ok {
//		t.Errorf("expected KeyringEntry to not be present")
//	}
//
//	if _, ok := cr.RemoveKeyring("foo"); ok {
//		t.Errorf("expected KeyringEntry to not have been removed")
//	}
//
//	if err := cr.AddKeyring("foo", nil); err == nil {
//		t.Errorf("expected error, got none")
//	}
//
//	if err := cr.AddKeyring("foo", mockKeyring); err != nil {
//		t.Errorf("expected no error, got %v", err)
//	}
//
//	if err := cr.AddKeyring("foo", mockKeyring); err == nil {
//		t.Error("expected error, got none")
//	}
//
//	if v, ok := cr.GetKeyring("foo"); !ok || v == nil {
//		t.Error("expected KeyringEntry to be present and not nil")
//	}
//
//	if v, ok := cr.RemoveKeyring("foo"); !ok || v == nil {
//		t.Error("expected KeyringEntry to have been removed and not nil")
//	}
//
//	if _, ok := cr.GetKeyring("foo"); ok {
//		t.Error("expected KeyringEntry to have been removed and not nil")
//	}
//}
//
//func TestCryptographicMaterialsManager_Padder(t *testing.T) {
//	cr := NewCryptographicMaterialsManager()
//
//	padder := &mockPadder{}
//
//	if _, ok := cr.GetPadder("foo"); ok {
//		t.Errorf("expected padder to not be present")
//	}
//
//	if _, ok := cr.RemovePadder("foo"); ok {
//		t.Errorf("expected padder to not have been removed")
//	}
//
//	if err := cr.AddPadder("foo", nil); err == nil {
//		t.Errorf("expected error, got none")
//	}
//
//	if err := cr.AddPadder("foo", padder); err != nil {
//		t.Errorf("expected no error, got %v", err)
//	}
//
//	if err := cr.AddPadder("foo", padder); err == nil {
//		t.Error("expected error, got none")
//	}
//
//	if v, ok := cr.GetPadder("foo"); !ok || v == nil {
//		t.Error("expected padder to be present and not nil")
//	}
//
//	if v, ok := cr.RemovePadder("foo"); !ok || v == nil {
//		t.Error("expected padder to have been removed and not nil")
//	}
//}
//
//func TestCryptographicMaterialsManager_valid(t *testing.T) {
//	cr := NewCryptographicMaterialsManager()
//
//	if err := cr.valid(); err == nil {
//		t.Errorf("expected error, got none")
//	} else if e, a := "at least one KeyringEntry must be provided", err.Error(); !strings.Contains(a, e) {
//		t.Errorf("expected %v, got %v", e, a)
//	}
//
//	if err := cr.AddKeyring("foo", func(envelope ObjectMetadata) (CipherDataDecrypter, error) {
//		return nil, nil
//	}); err != nil {
//		t.Fatalf("expected no error, got %v", err)
//	}
//	if err := cr.valid(); err == nil {
//		t.Fatalf("expected error, got none")
//	} else if e, a := "least one content decryption algorithms must be provided", err.Error(); !strings.Contains(a, e) {
//		t.Errorf("expected %v, got %v", e, a)
//	}
//
//	if err := cr.AddCEK("foo", func(data CryptographicMaterials) (ContentCipher, error) {
//		return nil, nil
//	}); err != nil {
//		t.Fatalf("expected no error, got %v", err)
//	}
//	if err := cr.valid(); err != nil {
//		t.Fatalf("expected no error, got %v", err)
//	}
//}

// TODO: This is more appropriate as a CMM unit test
//func TestRegisterAESCBCContentCipher(t *testing.T) {
//	cr := NewCryptographicMaterialsManager()
//	padder := AESCBCPadder
//	err := RegisterAESCBCContentCipher(cr, padder)
//	if err != nil {
//		t.Fatalf("expected no error, got %v", err)
//	}
//
//	if v, ok := cr.GetCEK("AES/CBC/PKCS5Padding"); !ok {
//		t.Fatal("expected cek algorithm handler to registered")
//	} else if v == nil {
//		t.Fatal("expected non-nil cek handler to be registered")
//	}
//
//	if v, ok := cr.GetPadder("AES/CBC/PKCS5Padding"); !ok {
//		t.Fatal("expected padder to be registered")
//	} else if v != padder {
//		t.Fatal("padder did not match provided value")
//	}
//
//	// try to register padder again
//	err = RegisterAESCBCContentCipher(cr, padder)
//	if err == nil {
//		t.Fatal("expected error, got none")
//	} else if !strings.Contains(err.Error(), "duplicate cek registry entry") {
//		t.Errorf("expected duplicate cek entry, got %v", err)
//	}
//
//	// try to regster padder with cek removed but padder entry still present
//	if _, ok := cr.RemoveCEK("AES/CBC/PKCS5Padding"); !ok {
//		t.Fatalf("expected value to be removed")
//	}
//	err = RegisterAESCBCContentCipher(cr, padder)
//	if err == nil {
//		t.Fatal("expected error, got none")
//	} else if !strings.Contains(err.Error(), "duplicate padder registry entry") {
//		t.Errorf("expected duplicate padder entry, got %v", err)
//	}
//}
