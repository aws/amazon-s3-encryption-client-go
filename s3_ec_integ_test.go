package s3crypto_test

import (
	"bytes"
	"context"
	s3crypto "github.com/aws/amazon-s3-encryption-client-go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"testing"
	"time"
)

func TestIntegS3ECHeadObject(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	// Ensure fresh key
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	cmm, err := s3crypto.NewCryptographicMaterialsManager(s3crypto.NewKmsKeyring(kmsClient, arn, func(options *s3crypto.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})

	s3EncryptionClient, err := s3crypto.NewS3EncryptionClientV3(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	result, err := s3EncryptionClient.GetObject(ctx, &s3.GetObjectInput{
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

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}

	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func TestIntegKmsContext(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test-kms-context" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	var matDesc s3crypto.MaterialDescription
	cmm, err := s3crypto.NewCryptographicMaterialsManager(s3crypto.NewKmsKeyring(kmsClient, arn, func(options *s3crypto.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})
	s3EncryptionClient, err := s3crypto.NewS3EncryptionClientV3(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader([]byte(plaintext)),
		Metadata: matDesc,
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	result, err := s3EncryptionClient.GetObject(ctx, &s3.GetObjectInput{
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

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}
	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func TestIntegKmsContextDecryptAny(t *testing.T) {
	var bucket = LoadBucket()
	var region = LoadRegion()
	var accountId = LoadAwsAccountId()
	var key = "single-round-trip-test-context-decrypt-any" + time.Now().String()
	var plaintext = "this is some plaintext to encrypt!"

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)

	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	var alias = LoadAwsKmsAlias()
	arn := getAliasArn(alias, region, accountId)
	if err != nil {
		t.Fatalf("failed to get fixture alias info for %s, %v", alias, err)
	}

	var s3Client = s3.NewFromConfig(cfg)

	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})

	kmsClient := kms.NewFromConfig(cfg)
	cmm, err := s3crypto.NewCryptographicMaterialsManager(s3crypto.NewKmsKeyring(kmsClient, arn, func(options *s3crypto.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	encryptionContext := context.WithValue(ctx, "EncryptionContext", map[string]string{"ec-key": "ec-value"})
	s3EncryptionClient, err := s3crypto.NewS3EncryptionClientV3(s3Client, cmm)
	_, err = s3EncryptionClient.PutObject(encryptionContext, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		t.Fatalf("error while encrypting: %v", err)
	}

	// decrypt with AnyKey
	anyKeyCmm, err := s3crypto.NewCryptographicMaterialsManager(s3crypto.NewKmsDecryptOnlyAnyKeyKeyring(kmsClient, func(options *s3crypto.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	s3EncryptionClientAnyKey, err := s3crypto.NewS3EncryptionClientV3(s3Client, anyKeyCmm)
	if err != nil {
		t.Fatalf("error while creating new CMM")
	}

	result, err := s3EncryptionClientAnyKey.GetObject(ctx, &s3.GetObjectInput{
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

	headResult, err := s3EncryptionClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if e, a := int64(len(plaintext)+16), headResult.ContentLength; e != a {
		t.Errorf("expect %v text, got %v", e, a)
	}
	// Cleanup
	s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}
