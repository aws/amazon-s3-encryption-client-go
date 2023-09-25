package s3crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func TestKmsContextKeyHandler_GenerateCipherDataWithCEKAlg(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		var body map[string]interface{}
		err = json.Unmarshal(bodyBytes, &body)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		md, ok := body["EncryptionContext"].(map[string]interface{})
		if !ok {
			w.WriteHeader(500)
			return
		}

		exEncContext := map[string]interface{}{
			"aws:" + cekAlgorithmHeader: "cekAlgValue",
		}

		if e, a := exEncContext, md; !reflect.DeepEqual(e, a) {
			w.WriteHeader(500)
			t.Errorf("expected %v, got %v", e, a)
			return
		}

		fmt.Fprintln(w, `{"CiphertextBlob":"AQEDAHhqBCCY1MSimw8gOGcUma79cn4ANvTtQyv9iuBdbcEF1QAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDJ6IcN5E4wVbk38MNAIBEIA7oF1E3lS7FY9DkoxPc/UmJsEwHzL82zMqoLwXIvi8LQHr8If4Lv6zKqY8u0+JRgSVoqCvZDx3p8Cn6nM=","KeyId":"arn:aws:kms:us-west-2:042062605278:key/c80a5cdb-8d09-4f9f-89ee-df01b2e3870a","Plaintext":"6tmyz9JLBE2yIuU7iXpArqpDVle172WSmxjcO6GNT7E="}`)
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	handler := NewKMSContextKeyGenerator(svc, "testid", nil)

	keySize := 32
	ivSize := 16

	cd, err := handler.GenerateCipherDataWithCEKAlg(context.Background(), keySize, ivSize, "cekAlgValue")
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if keySize != len(cd.Key) {
		t.Errorf("expected %d, but received %d", keySize, len(cd.Key))
	}
	if ivSize != len(cd.IV) {
		t.Errorf("expected %d, but received %d", ivSize, len(cd.IV))
	}
}

func TestKmsContextKeyHandler_GenerateCipherDataWithCEKAlg_ReservedKeyConflict(t *testing.T) {
	svc := kms.NewFromConfig(awstesting.Config())
	handler := NewKMSContextKeyGenerator(svc, "testid", MaterialDescription{
		"aws:x-amz-cek-alg": "something unexpected",
	})

	_, err := handler.GenerateCipherDataWithCEKAlg(context.Background(), 32, 16, "cekAlgValue")
	if err == nil {
		t.Errorf("expected error, but none")
	} else if !strings.Contains(err.Error(), "conflict in reserved KMS Encryption Context key aws:x-amz-cek-alg") {
		t.Errorf("expected reserved key error, got %v", err)
	}
}

func TestKmsContextKeyHandler_DecryptKey(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
			w.WriteHeader(500)
			return
		}

		var body map[string]interface{}
		err = json.Unmarshal(bodyBytes, &body)
		if err != nil {
			w.WriteHeader(500)
			return
		}

		if _, ok := body["KeyId"]; ok {
			t.Errorf("expected CMK to not be sent")
		}

		md, ok := body["EncryptionContext"].(map[string]interface{})
		if !ok {
			w.WriteHeader(500)
			return
		}

		exEncContext := map[string]interface{}{
			"aws:" + cekAlgorithmHeader: "AES/GCM/NoPadding",
		}

		if e, a := exEncContext, md; !reflect.DeepEqual(e, a) {
			w.WriteHeader(500)
			t.Errorf("expected %v, got %v", e, a)
			return
		}

		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"test-key-id","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	handler, err := newKMSContextKeyringEntryWithAnyCMK(svc)(Envelope{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err != nil {
		t.Fatalf("expected no error, but received %v", err)
	}

	plaintextKey, err := handler.DecryptKey([]byte{1, 2, 3, 4})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if !bytes.Equal(key, plaintextKey) {
		t.Errorf("expected %v, but received %v", key, plaintextKey)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MismatchCEK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	_, err := newKMSContextKeyringEntryWithAnyCMK(kmsClient)(Envelope{KeyringAlg: KMSContextKeyring, CEKAlg: "MismatchCEKValue", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	if e, a := "algorithm used at encryption time does not match the algorithm stored", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected error to contain %v, got %v", e, a)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MissingContextKey(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	_, err := newKMSContextKeyringEntryWithAnyCMK(kmsClient)(Envelope{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{}`})
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	if e, a := "missing from encryption context", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected error to contain %v, got %v", e, a)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MismatchKeyring(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	_, err := newKMSContextKeyringEntryWithAnyCMK(kmsClient)(Envelope{KeyringAlg: KMSKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{}`})
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	if e, a := "x-amz-cek-alg value `kms` did not match the expected algorithm `kms+context` for this handler", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected error to contain %v, got %v", e, a)
	}
}

func TestKmsContextKeyHandler_DecryptKey_WithCMK(t *testing.T) {
	key, _ := hex.DecodeString("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22")
	keyB64 := base64.URLEncoding.EncodeToString(key)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
			w.WriteHeader(500)
			return
		}

		if !bytes.Contains(body, []byte(`"KeyId":"thisKey"`)) {
			t.Errorf("expected CMK to be sent")
		}

		fmt.Fprintln(w, fmt.Sprintf("%s%s%s", `{"KeyId":"thisKey","Plaintext":"`, keyB64, `"}`))
	}))
	defer ts.Close()

	tConfig := awstesting.Config()
	tConfig.Region = "us-west-2"
	tConfig.RetryMaxAttempts = 0
	tConfig.EndpointResolverWithOptions = awstesting.TestEndpointResolver(ts.URL)
	svc := kms.NewFromConfig(tConfig)

	handler, err := newKMSContextKeyringEntryWithCMK(svc, "thisKey")(Envelope{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	_, err = handler.DecryptKey([]byte{1, 2, 3, 4})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
}

func TestRegisterKMSContextKeyringWithAnyCMK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())

	cr := NewCryptographicMaterialsManager()
	if err := RegisterKMSContextKeyringWithAnyCMK(cr, kmsClient); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if keyring, ok := cr.GetKeyring(KMSContextKeyring); !ok {
		t.Errorf("expected Keyring to be present")
	} else if keyring == nil {
		t.Errorf("expected Keyring to not be nil")
	}

	if err := RegisterKMSContextKeyringWithCMK(cr, kmsClient, "test-key-id"); err == nil {
		t.Error("expected error, got none")
	}
}

func TestRegisterKMSContextKeyringWithCMK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())

	cr := NewCryptographicMaterialsManager()
	if err := RegisterKMSContextKeyringWithCMK(cr, kmsClient, "cmkId"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if keyring, ok := cr.GetKeyring(KMSContextKeyring); !ok {
		t.Errorf("expected Keyring to be present")
	} else if keyring == nil {
		t.Errorf("expected Keyring to not be nil")
	}

	if err := RegisterKMSContextKeyringWithAnyCMK(cr, kmsClient); err == nil {
		t.Error("expected error, got none")
	}
}
