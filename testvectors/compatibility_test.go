package testvectors

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/amazon-s3-encryption-client-go/client"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
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
	"os"
	"testing"
)

const defaultBucket = "s3-encryption-client-v3-go-us-west-2"
const bucketEnvvar = "BUCKET"
const defaultAwsKmsAlias = "arn:aws:kms:us-west-2:657301468084:alias/s3-encryption-client-v3-go-us-west-2"

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

func TestKmsV1toV3_CBC(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_cbc"
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/V1toV3_CBC.txt"
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
	s3ecV3, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
	})

	result, err := s3ecV3.GetObject(ctx, &s3.GetObjectInput{
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

func TestKmsV1toV3_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/V1toV3_GCM.txt"
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
	s3ecV3, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
	})

	result, err := s3ecV3.GetObject(ctx, &s3.GetObjectInput{
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

func TestKmsContextV2toV3_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/V2toV3_GCM.txt"
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
	s3ecV3, err := client.New(s3V2, cmm)

	result, err := s3ecV3.GetObject(ctx, &s3.GetObjectInput{
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

func TestKmsContextV3toV2_GCM(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_gcm"
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/V3toV2_GCM.txt"
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
	s3ecV3, err := client.New(s3V2, cmm)

	_, err = s3ecV3.PutObject(ctx, &s3.PutObjectInput{
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

func TestInstructionFileV2toV3(t *testing.T) {
	bucket := LoadBucket()
	kmsKeyAlias := LoadAwsKmsAlias()

	cekAlg := "aes_cbc"
	key := "crypto_tests/" + cekAlg + "/v3/language_Go/inst_file_test.txt"
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
	s3ecV3, err := client.New(s3V2, cmm, func(clientOptions *client.EncryptionClientOptions) {
		clientOptions.EnableLegacyUnauthenticatedModes = true
	})

	result, err := s3ecV3.GetObject(ctx, &s3.GetObjectInput{
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
