package testvectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3crypto"
	"log"
	"os"
	"reflect"
	"testing"
)

// This is duplicated in integ_test.go,
// TODO: refactor to share
const defaultBucket = "s3-encryption-client-v3-go-us-west-2"
const bucketEnvvar = "BUCKET"
const defaultRegion = "us-west-2"
const regionEnvvar = "AWS_REGION"
const defaultAwsKmsAlias = "s3-encryption-client-v3-go-us-west-2"
const awsKmsAliasEnvvar = "AWS_KMS_ALIAS"
const awsAccountIdEnvvar = "AWS_ACCOUNT_ID"

func LoadBucket() string {
	if len(os.Getenv(bucketEnvvar)) > 0 {
		return os.Getenv(bucketEnvvar)
	} else {
		return defaultBucket
	}
}

func LoadRegion() string {
	if len(os.Getenv(regionEnvvar)) > 0 {
		return os.Getenv(regionEnvvar)
	} else {
		return defaultRegion
	}
}

func LoadAwsKmsAlias() string {
	if len(os.Getenv(awsKmsAliasEnvvar)) > 0 {
		return os.Getenv(awsKmsAliasEnvvar)
	} else {
		return defaultAwsKmsAlias
	}
}

func LoadAwsAccountId() string {
	return os.Getenv(awsAccountIdEnvvar)
}

// TestVectorManifest models the root of json schema
type TestVectorManifest struct {
	Manifest Manifest
	Keys     string
	Tests    map[string]TestEntry
}

type Manifest struct {
	Type    string
	Version int
}

type MasterKey struct {
	Type string
	Key  string
}

type TestEntry struct {
	Plaintext         string
	Algorithm         string
	ClientVersion     string            `json:"client-version"`
	KeyringAlgorithm  string            `json:"keyring-algorithm"`
	EncryptionContext map[string]string `json:"encryption-context"`
	MasterKeys        []MasterKey       `json:"master-keys"`
}

func loadTestVectorFile() TestVectorManifest {
	// TODO: actually read from a json file
	// for now just fake it
	jsonData := "{\n    \"manifest\": {\n        \"type\": \"s3ec-encrypt\",\n        \"version\": 1\n    },\n    \"keys\": \"file://CANONICAL-GENERATED-MANIFESTS/0002-keys.v3.json\",\n    \"tests\": {\n        \"b5725467-f56d-4b68-bf7f-bec389037245\": {\n            \"plaintext\": \"Giants and the geni, multiplex of wing and eye...\",\n            \"algorithm\": \"0072\",\n            \"client-version\": \"v1\",\n            \"keyring-algorithm\": \"kms\",\n            \"encryption-context\": {\n                \"key1\": \"val1\",\n                \"key2\": \"val2\"\n            },\n            \"master-keys\": [{\n                \"type\": \"aws-kms\",\n                \"key\": \"us-west-2-decryptable\"\n            }, {\n                \"type\": \"aws-kms\",\n                \"key\": \"us-west-2-encrypt-only\"\n            }]\n        }\n    }\n}"

	var manifest TestVectorManifest
	err := json.Unmarshal([]byte(jsonData), &manifest)
	if err != nil {
		fmt.Errorf("failed to unmarshal KAT json file: %v", err)
	}
	return manifest
}

func TestRunTestVectors(t *testing.T) {
	// TODO: just testing JSON stuff for now
	manifestContent := loadTestVectorFile()
	fmt.Println("testvector manifest: ")
	fmt.Println(manifestContent)

	// TODO: Can define == on TestVectorManifest, but we're just testing so
	if (reflect.DeepEqual(manifestContent, TestVectorManifest{})) {
		t.Fatalf("manifest is empty, but expected something!")
	}

	fmt.Println("now let's try to use it?")
	for k, v := range manifestContent.Tests {
		fmt.Printf("test case: [%s]\n", k)
		fmt.Printf("---- ----: [%s]\n", v.Algorithm)
		fmt.Printf("---- ----: [%s]\n", v.ClientVersion)
		fmt.Printf("---- ----: [%s]\n", v.KeyringAlgorithm)
		fmt.Printf("---- ----: [%s]\n", v.Plaintext)
		fmt.Printf("---- ----: [%s]\n", v.EncryptionContext)
		for _, v2 := range v.MasterKeys {
			fmt.Println("---- ---- MasterKey:")
			fmt.Printf("---- ---- Type: [%s]\n", v2.Type)
			fmt.Printf("---- ---- Key: [%s]\n", v2.Key)
		}
	}

	// Hardcode bucket, key, KMS key, plaintext for now

	// The way the Go integ tests are setup is a little weird
	// It looks for plaintext test cases,
	// and tries to decrypt them later.
	// In many cases, the client cannot encrypt the plaintext cases,
	// so it is forced to assume that the right ciphertexts will be
	// present.

	// For example, for AES GCM, there are two relevant paths:
	// s3://s3-encryption-client-v3-go-justplaz-us-west-2/crypto_tests/aes_gcm/v3/language_Go/ciphertext_test_case_aes_gcm_test_four.txt
	// s3://s3-encryption-client-v3-go-justplaz-us-west-2/crypto_tests/aes_gcm/plaintext_test_case_aes_gcm_test_four.txt

	// Ideally, this little program would be smart enough to read from my local test files
	// and encrypt them using the legacy v2 client, but it isn't.
	// Instead, just manually point the `putObject` call to the right place...

	bucket := LoadBucket()
	// TODO: load from vectors
	kmsKeyAlias := LoadAwsKmsAlias()

	// TODO: load from vectors
	cekAlg := "aes_cbc"
	// TODO: it'd be nice to have the KEK Alg in the path/key as well
	// do we still need the client version?
	// maybe, if we want to distinguish i.e. AESGCM/KMS+Context v2 and v3
	// probably worth bothering with,
	// since v3 tests can encrypt but v2 can't
	// NOTE: This path matches what the integ_test.go looks for, but it doesn't need to (and maybe shouldn't?)
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/ciphertext_test_case_jgp_test_one.txt"
	region := "us-west-2"
	// TODO: Read more text from files
	plaintext := "This is a test.\n"
	var handler s3crypto.CipherDataGenerator
	sessKms, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kms.New(sessKms)
	handler = s3crypto.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-CBC content cipher
	builder := s3crypto.AESCBCContentCipherBuilder(handler, s3crypto.AESCBCPadder)
	//sess := session.Must(session.NewSession())
	encClient := s3crypto.NewEncryptionClient(sessKms, builder)

	_, err = encClient.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)
}
