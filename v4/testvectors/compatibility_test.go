// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testvectors

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/v4/client"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsV1 "github.com/aws/aws-sdk-go/aws"
	sessionV1 "github.com/aws/aws-sdk-go/aws/session"
	kmsV1 "github.com/aws/aws-sdk-go/service/kms"
	s3V1 "github.com/aws/aws-sdk-go/service/s3"
	s3cryptoV2 "github.com/aws/aws-sdk-go/service/s3/s3crypto"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"testing"
	"time"
)

const defaultBucket = "s3ec-go-github-test-bucket"
const bucketEnvvar = "BUCKET"
const defaultAwsKmsAlias = "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Go-Github-KMS-Key"

const awsKmsAliasEnvvar = "AWS_KMS_ALIAS"
const awsAccountIdEnvvar = "AWS_ACCOUNT_ID"
const defaultRegion = "us-west-2"
const regionEnvvar = "AWS_REGION"

func LoadRegion() string {
	if len(os.Getenv(regionEnvvar)) > 0 {
		return os.Getenv(regionEnvvar)
	} else {
		return defaultRegion
	}
}

func LoadBucket() string {
	if len(os.Getenv(bucketEnvvar)) > 0 {
		return os.Getenv(bucketEnvvar)
	} else {
		return defaultBucket
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

// This generates CBC ciphertexts that the s3_integ_test decrypts.
// This is meant to be a utility function, not a test function,
// but for simplicity and easy invocation it is a test function.
// To avoid running it each test run, it is left commented out.
// func TestGenerateCBCIntegTests(t *testing.T) {
// 	arn := "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Go-Github-KMS-Key"
// 	bucket := "s3ec-go-github-test-bucket"
// 	region := "us-west-2"
// 	ctx := context.Background()
// 	cfg, _ := config.LoadDefaultConfig(ctx,
// 		config.WithRegion(region),
// 	)

// 	s3Client := s3.NewFromConfig(cfg)
// 	fixtures := getFixtures(t, s3Client, "aes_cbc", bucket)
// 	// V2 client
// 	var handler s3cryptoV2.CipherDataGenerator
// 	sessKms, _ := sessionV1.NewSession(&awsV1.Config{
// 		Region: aws.String(region),
// 	})

// 	// KMS v1
// 	kmsSvc := kmsV1.New(sessKms)
// 	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, arn)
// 	// AES-CBC content cipher
// 	builder := s3cryptoV2.AESCBCContentCipherBuilder(handler, s3cryptoV2.AESCBCPadder)
// 	encClient := s3cryptoV2.NewEncryptionClient(sessKms, builder)

// 	for caseKey, plaintext := range fixtures.Plaintexts {
// 		_, err := encClient.PutObject(&s3V1.PutObjectInput{
// 			Bucket: aws.String(bucket),
// 			Key: aws.String(
// 				fmt.Sprintf("%s/%s/language_Go/ciphertext_test_case_%s",
// 					fixtures.BaseFolder, version, caseKey),
// 			),
// 			Body: bytes.NewReader(plaintext),
// 		})
// 		if err != nil {
// 			t.Fatalf("failed to upload encrypted fixture, %v", err)
// 		}
// 	}

// }

func TestKmsV1toV4_CBC(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_cbc"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/V1toV4_CBC_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 client
	var handler s3cryptoV2.CipherDataGenerator
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-CBC content cipher
	builder := s3cryptoV2.AESCBCContentCipherBuilder(handler, s3cryptoV2.AESCBCPadder)
	encClient := s3cryptoV2.NewEncryptionClient(sessKms, builder)

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestKmsV1toV4_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/V1toV4_GCM_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 client
	var handler s3cryptoV2.CipherDataGenerator
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-GCM content cipher
	builder := s3cryptoV2.AESGCMContentCipherBuilder(handler)
	encClient := s3cryptoV2.NewEncryptionClient(sessKms, builder)

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestKmsContextV2toV4_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/V2toV4_GCM_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 client
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	handler := s3cryptoV2.NewKMSContextKeyGenerator(kmsSvc, kmsKeyAlias, s3cryptoV2.MaterialDescription{})
	// AES-GCM content cipher
	builder := s3cryptoV2.AESGCMContentCipherBuilderV2(handler)
	encClient, err := s3cryptoV2.NewEncryptionClientV2(sessKms, builder)
	if err != nil {
		log.Fatalf("error creating new v2 client: %v", err)
	}

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestKmsContextV4toV2_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/V4toV2_GCM_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	_, err = s3ecV4.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	// V2 client
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	cr := s3cryptoV2.NewCryptoRegistry()
	s3cryptoV2.RegisterKMSContextWrapWithCMK(cr, kmsSvc, kmsKeyAlias)
	s3cryptoV2.RegisterAESGCMContentCipher(cr)
	decClient, err := s3cryptoV2.NewDecryptionClientV2(sessKms, cr)
	if err != nil {
		log.Fatalf("error creating new v2 client: %v", err)
	}

	result, err := decClient.GetObject(&s3V1.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestInstructionFileV2toV4(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_cbc"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/inst_file_test_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 client
	var handler s3cryptoV2.CipherDataGenerator
	sessV1, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessV1)
	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-CBC content cipher
	builder := s3cryptoV2.AESCBCContentCipherBuilder(handler, s3cryptoV2.AESCBCPadder)
	encClient := s3cryptoV2.NewEncryptionClient(sessV1, builder, func(clientOpts *s3cryptoV2.EncryptionClient) {
		clientOpts.SaveStrategy = s3cryptoV2.S3SaveStrategy{
			Client: s3V1.New(sessV1),
		}
	})

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting: %v", err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array: %v", err)
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestNegativeKeyringOption(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_cbc"
	key := "crypto_tests/" + cekAlg + "/v4/language_Go/NegativeV1toV4_CBC_" + uniqueSuffix() + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 Client
	var handler s3cryptoV2.CipherDataGenerator
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-CBC content cipher
	builder := s3cryptoV2.AESCBCContentCipherBuilder(handler, s3cryptoV2.AESCBCPadder)
	encClient := s3cryptoV2.NewEncryptionClient(sessKms, builder)

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
	})

	_, err = s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		t.Fatalf("error while calling GetObject, expected to FAIL")
	}
}

func TestEnableLegacyDecryptBothFormats(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlgCbc := "aes_cbc"
	suffix := uniqueSuffix()
	keyCbc := "crypto_tests/" + cekAlgCbc + "/v4/language_Go/BothFormats_CBC_" + suffix + ".txt"
	cekAlgGcm := "aes_gcm"
	keyGcm := "crypto_tests/" + cekAlgGcm + "/v4/language_Go/BothFormats_GCM_" + suffix + ".txt"
	region := "us-west-2"
	plaintext := "This is a test.\n"

	// V2 Client
	var handler s3cryptoV2.CipherDataGenerator
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
		Region: aws.String(region),
	})

	// KMS v1
	kmsSvc := kmsV1.New(sessKms)
	handler = s3cryptoV2.NewKMSKeyGenerator(kmsSvc, kmsKeyAlias)
	// AES-CBC content cipher
	builder := s3cryptoV2.AESCBCContentCipherBuilder(handler, s3cryptoV2.AESCBCPadder)
	encClient := s3cryptoV2.NewEncryptionClient(sessKms, builder)

	_, err = encClient.PutObject(&s3V1.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(keyCbc),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, keyCbc)

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	_, err = s3ecV4.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(keyGcm),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("error while calling PutObject: %v", err)
	}

	getResponseCbc, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(keyCbc),
	})
	if err != nil {
		t.Fatalf("error while calling GetObject for CBC: %v", err)
	}
	// ensure CBC matches
	decryptedPlaintext, err := io.ReadAll(getResponseCbc.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array: %v", err)
	}
	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	getResponseGcm, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(keyGcm),
	})
	if err != nil {
		t.Fatalf("error while calling GetObject for GCM: %v", err)
	}
	// ensure GCM matches
	decryptedPlaintext, err = io.ReadAll(getResponseGcm.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array: %v", err)
	}
	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}
}

func TestUnicodeEncryptionContextV4ClientV2MessageFormat(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#v1-v2-shared
	//= type=test
	//# - This string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	//= ../specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
	//= type=test
	//# - The S3EC SHOULD support decoding the S3 Server's "double encoding".
	rune128 := string(rune(128))
	rune200 := string(rune(200))
	rune256 := string(rune(256))
	runeMaxInt := string(rune(math.MaxInt32))
	shorter := "我"
	medium := "Brøther, may I have the lööps"
	longer := "我的资我的资源我的资源我的资源的资源源"
	mix := "hello 我的资我的资源我的资源我的资源的资源源 goodbye"
	mixTwo := "hello 我的资我的资源我的资源我的资源的资源源 goodbye我的资"

	unicodeStrings := []string{rune128, rune200, rune256, runeMaxInt, shorter, medium, longer, mix, mixTwo}
	for _, s := range unicodeStrings {
		UnicodeEncryptionContextV4ClientV2MessageFormat(t, s)
	}
}

func UnicodeEncryptionContextV4ClientV2MessageFormat(t *testing.T, metadataString string) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	random := rand.Int()
	key := "unicode-encryption-context-" + time.Now().String() + fmt.Sprintf("%d", random)
	region := "us-west-2"
	plaintext := "This is a test.\n"
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
		clientOptions.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": metadataString})
	_, err = s3ecV4.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}

	time.Sleep(1 * time.Second)

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting object (%s): %v", key, err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	s3ecV4.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func TestUnicodeMaterialDescriptionV4ClientV3MessageFormat(t *testing.T) {
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	//= ../specification/s3-encryption/data-format/content-metadata.md#v3-only
	//= type=test
	//# This encryption context string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
	rune128 := string(rune(128))
	rune200 := string(rune(200))
	rune256 := string(rune(256))
	runeMaxInt := string(rune(math.MaxInt32))
	shorter := "我"
	medium := "Brøther, may I have the lööps"
	longer := "我的资我的资源我的资源我的资源的资源源"
	mix := "hello 我的资我的资源我的资源我的资源的资源源 goodbye"
	mixTwo := "hello 我的资我的资源我的资源我的资源的资源源 goodbye我的资"

	unicodeStrings := []string{rune128, rune200, rune256, runeMaxInt, shorter, medium, longer, mix, mixTwo}
	for _, s := range unicodeStrings {
		UnicodeMaterialDescriptionV4ClientV3MessageFormat(t, s)
	}
}

func UnicodeMaterialDescriptionV4ClientV3MessageFormat(t *testing.T, metadataString string) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	random := rand.Int()
	key := "unicode-material-description-" + time.Now().String() + fmt.Sprintf("%d", random)
	region := "us-west-2"
	plaintext := "This is a test.\n"
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	kmsV2 := kms.NewFromConfig(cfg)
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = true
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	s3V2 := s3.NewFromConfig(cfg)
	s3ecV4, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
	})

	// Create material description with Unicode string
	materialDescription := materials.MaterialDescription{"md-key": metadataString}
	_, err = s3ecV4.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader([]byte(plaintext)),
		Metadata: materialDescription,
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}

	time.Sleep(1 * time.Second)

	result, err := s3ecV4.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("error while decrypting object (%s): %v", key, err)
	}

	decryptedPlaintext, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("failed to read decrypted plaintext into byte array")
	}

	if e, a := []byte(plaintext), decryptedPlaintext; !bytes.Equal(e, a) {
		t.Errorf("expect %v text, got %v", e, a)
	}

	s3ecV4.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}
