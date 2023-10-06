package s3crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/internal/awstesting"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
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

	keySize := 32
	ivSize := 16

	keyring := NewKmsContextKeyring(svc, "testid", nil)
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Fatalf("failed to create new CMM")
	}
	materials := cmm.getEncryptionMaterials()
	// TODO: This is actually calling KMS, which is almost certainly wrong
	// TODO: Debug the old test to see how it was mocked
	cd, err := keyring.OnEncrypt(context.Background(), materials)
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
	keyring := NewKmsContextKeyring(svc, "testid", MaterialDescription{
		"aws:x-amz-cek-alg": "something unexpected",
	})
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Fatalf("failed to create new CMM")
	}
	materials := cmm.getEncryptionMaterials()
	_, err = keyring.OnEncrypt(context.Background(), materials)
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

	keyring := NewKmsContextAnyKeyKeyring(svc)
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	materials, err := cmm.decryptMaterials(context.Background(), ObjectMetadata{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}

	if !bytes.Equal(key, materials.Key) {
		t.Errorf("expected %v, but received %v", key, materials.Key)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MismatchCEK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	keyring := NewKmsContextAnyKeyKeyring(kmsClient)
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	_, err = cmm.decryptMaterials(context.Background(), ObjectMetadata{KeyringAlg: KMSContextKeyring, CEKAlg: "MismatchCEKValue", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	if e, a := "algorithm used at encryption time does not match the algorithm stored", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected error to contain %v, got %v", e, a)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MissingContextKey(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	keyring := NewKmsContextAnyKeyKeyring(kmsClient)
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	_, err = cmm.decryptMaterials(context.Background(), ObjectMetadata{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{}`})
	if err == nil {
		t.Fatal("expected error, but got none")
	}

	if e, a := "missing from encryption context", err.Error(); !strings.Contains(a, e) {
		t.Errorf("expected error to contain %v, got %v", e, a)
	}
}

func TestKmsContextKeyHandler_decryptHandler_MismatchKeyring(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	keyring := NewKmsContextAnyKeyKeyring(kmsClient)
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	_, err = cmm.decryptMaterials(context.Background(), ObjectMetadata{KeyringAlg: KMSKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{}`})
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

	keyring := NewKmsContextKeyring(svc, "thisKey", MaterialDescription{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"})
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("failed to create new cmm: %v", err)
	}
	_, err = cmm.decryptMaterials(context.Background(), ObjectMetadata{KeyringAlg: KMSContextKeyring, CEKAlg: "AES/GCM/NoPadding", MatDesc: `{"aws:x-amz-cek-alg": "AES/GCM/NoPadding"}`})
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
}

func TestRegisterKMSContextKeyringWithAnyCMK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())

	keyring := NewKmsContextAnyKeyKeyring(kmsClient)
	cr, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("failed to create new CMM")
	}

	if cr.Keyring == nil {
		t.Errorf("expected Keyring to not be nil")
	}
}

func TestRegisterKMSContextKeyringWithCMK(t *testing.T) {
	kmsClient := kms.NewFromConfig(awstesting.Config())
	keyring := NewKmsContextKeyring(kmsClient, "cmkId", MaterialDescription{})
	cmm, err := NewCryptographicMaterialsManager(keyring)
	if err != nil {
		t.Errorf("failed to create new CMM")
	}

	if cmm.Keyring == nil {
		t.Errorf("expected KeyringEntry to not be nil")
	}
}
