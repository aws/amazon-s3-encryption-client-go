package s3crypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestKeyringFactory(t *testing.T) {
	tConfig := awstesting.Config()
	kmsClient := kms.NewFromConfig(tConfig)

	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
			KMSKeyring: (kmsKeyHandler{
				apiClient: kmsClient,
			}).decryptHandler,
		}, map[string]CEKEntry{
			AESGCMNoPadding: newAESGCMContentCipher,
		}, map[string]Padder{}),
	}
	env := Envelope{
		KeyringAlg: KMSKeyring,
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)
	w, ok := keyring.(*kmsKeyHandler)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if keyring == nil {
		t.Error("expected non-nil value")
	}
	if !ok {
		t.Errorf("expected kmsKeyHandler, but received %v", *w)
	}
}
func TestKeyringFactoryErrorNoKeyring(t *testing.T) {
	tConfig := awstesting.Config()
	kmsClient := kms.NewFromConfig(tConfig)
	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
			KMSKeyring: (kmsKeyHandler{
				apiClient: kmsClient,
			}).decryptHandler,
		}, map[string]CEKEntry{
			AESGCMNoPadding: newAESGCMContentCipher,
		}, map[string]Padder{}),
	}
	env := Envelope{
		KeyringAlg: "none",
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)

	if err == nil {
		t.Error("expected error, but received none")
	}
	if keyring != nil {
		t.Errorf("expected nil Keyring value, received %v", keyring)
	}
}

func TestKeyringFactoryCustomEntry(t *testing.T) {
	tConfig := awstesting.Config()
	kmsClient := kms.NewFromConfig(tConfig)
	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
			"custom": (kmsKeyHandler{
				apiClient: kmsClient,
			}).decryptHandler,
		}, map[string]CEKEntry{
			AESGCMNoPadding: newAESGCMContentCipher,
		}, map[string]Padder{}),
	}
	env := Envelope{
		KeyringAlg: "custom",
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if keyring == nil {
		t.Errorf("expected nil keyring value, received %v", keyring)
	}
}

func TestCEKFactory(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(map[string]KeyringEntry{
			KMSKeyring: (kmsKeyHandler{
				apiClient: svc,
			}).decryptHandler,
		}, map[string]CEKEntry{
			AESGCMNoPadding: newAESGCMContentCipher,
		}, map[string]Padder{
			NoPadder.Name(): NoPadder,
		}),
	}
	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	ivB64 := base64.URLEncoding.EncodeToString(iv)

	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)

	env := Envelope{
		KeyringAlg: KMSKeyring,
		CEKAlg:     AESGCMNoPadding,
		CipherKey:  cipherKeyB64,
		IV:         ivB64,
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if cek == nil {
		t.Errorf("expected non-nil cek")
	}
}

func TestCEKFactoryNoCEK(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(
			map[string]KeyringEntry{
				KMSKeyring: (kmsKeyHandler{
					apiClient: svc,
				}).decryptHandler,
			},
			map[string]CEKEntry{
				AESGCMNoPadding: newAESGCMContentCipher,
			},
			map[string]Padder{
				NoPadder.Name(): NoPadder,
			}),
	}
	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	ivB64 := base64.URLEncoding.EncodeToString(iv)

	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)

	env := Envelope{
		KeyringAlg: KMSKeyring,
		CEKAlg:     "none",
		CipherKey:  cipherKeyB64,
		IV:         ivB64,
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)

	if err == nil {
		t.Error("expected error, but received none")
	}
	if cek != nil {
		t.Errorf("expected nil cek value, received %v", keyring)
	}
}

func TestCEKFactoryCustomEntry(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	o := EncryptionClientOptions{
		CryptographicMaterialsManager: initCryptographicMaterialsManagerFrom(
			map[string]KeyringEntry{
				KMSKeyring: (kmsKeyHandler{
					apiClient: svc,
				}).decryptHandler,
			}, map[string]CEKEntry{
				"custom": newAESGCMContentCipher,
			}, map[string]Padder{}),
	}
	iv, err := hex.DecodeString("0d18e06c7c725ac9e362e1ce")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	ivB64 := base64.URLEncoding.EncodeToString(iv)

	cipherKey, err := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	cipherKeyB64 := base64.URLEncoding.EncodeToString(cipherKey)

	env := Envelope{
		KeyringAlg: KMSKeyring,
		CEKAlg:     "custom",
		CipherKey:  cipherKeyB64,
		IV:         ivB64,
		MatDesc:    `{"kms_cmk_id":""}`,
	}
	keyring, err := KeyringFromEnvelope(o, env)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	cek, err := cekFromEnvelope(context.Background(), o, env, keyring)

	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if cek == nil {
		t.Errorf("expected non-nil cek")
	}
}
