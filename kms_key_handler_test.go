package s3crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestKmsKeyHandler_DecryptKey(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
			w.WriteHeader(500)
			return
		}
		if bytes.Contains(body, []byte(`"KeyId":"test"`)) {
			t.Errorf("expected CMK to not be sent")
		}
		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)
	handler, err := (kmsKeyHandler{apiClient: svc}).decryptHandler(Envelope{KeyringAlg: KMSKeyring, MatDesc: `{"kms_cmk_id":"test"}`})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	plaintextKey, err := handler.DecryptKey([]byte{1, 2, 3, 4})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if !bytes.Equal(key, plaintextKey) {
		t.Errorf("expected %v, but received %v", key, plaintextKey)
	}
}

func TestKmsKeyHandler_DecryptKey_WithCMK(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
			w.WriteHeader(500)
			return
		}

		if !bytes.Contains(body, []byte(`"KeyId":"thisKey"`)) {
			t.Errorf("expected CMK to be sent")
		}

		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)
	handler, err := newKMSKeyringEntryWithCMK(svc, "thisKey")(Envelope{KeyringAlg: KMSKeyring, MatDesc: `{"kms_cmk_id":"test"}`})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	plaintextKey, err := handler.DecryptKey([]byte{1, 2, 3, 4})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if !bytes.Equal(key, plaintextKey) {
		t.Errorf("expected %v, but received %v", key, plaintextKey)
	}
}

func TestRegisterKMSKeyringWithAnyCMK(t *testing.T) {
	tConfig := awstesting.Config()
	kmsClient := kms.NewFromConfig(tConfig)

	cr := NewCryptographicMaterialsManager()
	if err := RegisterKMSKeyringWithAnyCMK(cr, kmsClient); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if keyring, ok := cr.GetKeyring(KMSKeyring); !ok {
		t.Errorf("expected Keyring to be present")
	} else if keyring == nil {
		t.Errorf("expected Keyring to not be nil")
	}

	if err := RegisterKMSKeyringWithCMK(cr, kmsClient, "test-key-id"); err == nil {
		t.Error("expected error, got none")
	}
}

func TestRegisterKMSKeyringWithCMK(t *testing.T) {
	tConfig := awstesting.Config()
	kmsClient := kms.NewFromConfig(tConfig)

	cr := NewCryptographicMaterialsManager()
	if err := RegisterKMSKeyringWithCMK(cr, kmsClient, "cmkId"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if keyring, ok := cr.GetKeyring(KMSKeyring); !ok {
		t.Errorf("expected Keyring to be present")
	} else if keyring == nil {
		t.Errorf("expected Keyring to not be nil")
	}

	if err := RegisterKMSKeyringWithAnyCMK(cr, kmsClient); err == nil {
		t.Error("expected error, got none")
	}
}
