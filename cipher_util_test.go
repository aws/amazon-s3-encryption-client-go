package s3crypto

// TODO: Update to use new funcs
// TODO: keyringFromEnvelope becomes decryptMaterials
//func TestKeyringFactory(t *testing.T) {
//	tConfig := awstesting.Config()
//	kmsClient := kms.NewFromConfig(tConfig)
//
//	o := EncryptionClientOptions{
//		// TODO: Just create a new cmm
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
//			KMSKeyring: (kmsKeyHandler{
//				apiClient: kmsClient,
//			}).decryptHandler,
//		}, map[string]CEKEntry{
//			AESGCMNoPadding: newAESGCMContentCipher,
//		}, map[string]Padder{}),
//	}
//	env := ObjectMetadata{
//		KeyringAlg: KMSKeyring,
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//	w, ok := keyring.(*kmsKeyHandler)
//
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	if keyring == nil {
//		t.Error("expected non-nil value")
//	}
//	if !ok {
//		t.Errorf("expected kmsKeyHandler, but received %v", *w)
//	}
//}
//func TestKeyringFactoryErrorNoKeyring(t *testing.T) {
//	tConfig := awstesting.Config()
//	kmsClient := kms.NewFromConfig(tConfig)
//	o := EncryptionClientOptions{
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
//			KMSKeyring: (kmsKeyHandler{
//				apiClient: kmsClient,
//			}).decryptHandler,
//		}, map[string]CEKEntry{
//			AESGCMNoPadding: newAESGCMContentCipher,
//		}, map[string]Padder{}),
//	}
//	env := ObjectMetadata{
//		KeyringAlg: "none",
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//
//	if err == nil {
//		t.Error("expected error, but received none")
//	}
//	if keyring != nil {
//		t.Errorf("expected nil KeyringEntry value, received %v", keyring)
//	}
//}
//
//func TestKeyringFactoryCustomEntry(t *testing.T) {
//	tConfig := awstesting.Config()
//	kmsClient := kms.NewFromConfig(tConfig)
//	o := EncryptionClientOptions{
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
//			"custom": (kmsKeyHandler{
//				apiClient: kmsClient,
//			}).decryptHandler,
//		}, map[string]CEKEntry{
//			AESGCMNoPadding: newAESGCMContentCipher,
//		}, map[string]Padder{}),
//	}
//	env := ObjectMetadata{
//		KeyringAlg: "custom",
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	if keyring == nil {
//		t.Errorf("expected nil keyring value, received %v", keyring)
//	}
//}
//
//func TestCEKFactory(t *testing.T) {
//	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	keyB64 := base64.URLEncoding.EncodeToString(key)
//	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
//	}))
//	defer ts.Close()
//
//	tConfig := awstesting.Config()
//	tConfig.Region = "us-west-2"
//	tConfig.RetryMaxAttempts = 0
//	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
//	svc := kms.NewFromConfig(tConfig)
//
//	o := EncryptionClientOptions{
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
//			KMSKeyring: (kmsKeyHandler{
//				apiClient: svc,
//			}).decryptHandler,
//		}, map[string]CEKEntry{
//			AESGCMNoPadding: newAESGCMContentCipher,
//		}, map[string]Padder{
//			NoPadder.Name(): NoPadder,
//		}),
//	}
//	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	ivB64 := base64.URLEncoding.EncodeToString(iv)
//
//	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)
//
//	env := ObjectMetadata{
//		KeyringAlg: KMSKeyring,
//		CEKAlg:     AESGCMNoPadding,
//		CipherKey:  cipherKeyB64,
//		IV:         ivB64,
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//
//	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)
//
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	if cek == nil {
//		t.Errorf("expected non-nil cek")
//	}
//}
//
//func TestCEKFactoryNoCEK(t *testing.T) {
//	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	keyB64 := base64.URLEncoding.EncodeToString(key)
//	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
//	}))
//	defer ts.Close()
//
//	tConfig := awstesting.Config()
//	tConfig.Region = "us-west-2"
//	tConfig.RetryMaxAttempts = 0
//	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
//	svc := kms.NewFromConfig(tConfig)
//
//	o := EncryptionClientOptions{
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(
//			map[string]KeyringEntry{
//				KMSKeyring: (kmsKeyHandler{
//					apiClient: svc,
//				}).decryptHandler,
//			},
//			map[string]CEKEntry{
//				AESGCMNoPadding: newAESGCMContentCipher,
//			},
//			map[string]Padder{
//				NoPadder.Name(): NoPadder,
//			}),
//	}
//	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	ivB64 := base64.URLEncoding.EncodeToString(iv)
//
//	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)
//
//	env := ObjectMetadata{
//		KeyringAlg: KMSKeyring,
//		CEKAlg:     "none",
//		CipherKey:  cipherKeyB64,
//		IV:         ivB64,
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//
//	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)
//
//	if err == nil {
//		t.Error("expected error, but received none")
//	}
//	if cek != nil {
//		t.Errorf("expected nil cek value, received %v", keyring)
//	}
//}
//
//func TestCEKFactoryCustomEntry(t *testing.T) {
//	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	keyB64 := base64.URLEncoding.EncodeToString(key)
//	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
//	}))
//	defer ts.Close()
//
//	tConfig := awstesting.Config()
//	tConfig.Region = "us-west-2"
//	tConfig.RetryMaxAttempts = 0
//	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
//	svc := kms.NewFromConfig(tConfig)
//
//	o := EncryptionClientOptions{
//		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(
//			map[string]KeyringEntry{
//				KMSKeyring: (kmsKeyHandler{
//					apiClient: svc,
//				}).decryptHandler,
//			}, map[string]CEKEntry{
//				"custom": newAESGCMContentCipher,
//			}, map[string]Padder{}),
//	}
//	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	ivB64 := base64.URLEncoding.EncodeToString(iv)
//
//	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)
//
//	env := ObjectMetadata{
//		KeyringAlg: KMSKeyring,
//		CEKAlg:     "custom",
//		CipherKey:  cipherKeyB64,
//		IV:         ivB64,
//		MatDesc:    `{"kms_cmk_id":""}`,
//	}
//	keyring, err := keyringFromEnvelope(o, env)
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//
//	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)
//
//	if err != nil {
//		t.Errorf("expected no error, but received %v", err)
//	}
//	if cek == nil {
//		t.Errorf("expected non-nil cek")
//	}
//}
