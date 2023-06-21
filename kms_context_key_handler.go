package s3crypto

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const (
	// KMSContextWrap is a constant used during decryption to build a kms+context key handler
	KMSContextWrap      = "kms+context"
	kmsAWSCEKContextKey = "aws:" + cekAlgorithmHeader

	kmsReservedKeyConflictErrMsg = "conflict in reserved KMS Encryption Context key %s. This value is reserved for the S3 Encryption Client and cannot be set by the user"
	kmsMismatchCEKAlg            = "the content encryption algorithm used at encryption time does not match the algorithm stored for decryption time. The object may be altered or corrupted"
)

// KmsAPIClient is a client that implements the GenerateDataKey and Decrypt operations
type KmsAPIClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// NewKMSContextKeyGenerator builds a new kms+context key provider using the customer key ID and material
// description.
//
// Example:
//
//	ctx := context.Background()
//	cfg, err := config.LoadDefaultConfig(ctx)
//	if err != nil {
//		panic(err) // handle err
//	}
//
//	cmkID := "KMS Key ARN"
//	var matdesc s3crypto.MaterialDescription
//	handler := s3crypto.NewKMSContextKeyGenerator(kms.NewFromConfig(cfg), cmkID, matdesc)
func NewKMSContextKeyGenerator(apiClient KmsAPIClient, cmkID string, matdesc MaterialDescription) CipherDataGeneratorWithCEKAlg {
	return newKMSContextKeyHandler(apiClient, cmkID, matdesc)
}

// RegisterKMSContextWrapWithCMK registers the kms+context wrapping algorithm to the given WrapRegistry. The wrapper
// will be configured to only call KMS Decrypt using the provided CMK.
//
// Example:
//
//	cr := s3crypto.NewCryptoRegistry()
//	if err := RegisterKMSContextWrapWithCMK(); err != nil {
//		panic(err) // handle error
//	}
func RegisterKMSContextWrapWithCMK(registry *CryptoRegistry, apiClient KmsAPIClient, cmkID string) error {
	if registry == nil {
		return errNilCryptoRegistry
	}
	return registry.AddWrap(KMSContextWrap, newKMSContextWrapEntryWithCMK(apiClient, cmkID))
}

// RegisterKMSContextWrapWithAnyCMK registers the kms+context wrapping algorithm to the given WrapRegistry. The wrapper
// will be configured to call KMS decrypt without providing a CMK.
//
// Example:
//
//	ctx := context.Background()
//	cfg, err := config.LoadDefaultConfig(ctx)
//	if err != nil {
//		panic(err) // handle err
//	}
//
//	cr := s3crypto.NewCryptoRegistry()
//	if err := s3crypto.RegisterKMSContextWrapWithAnyCMK(cr, kms.NewFromConfig(cfg)); err != nil {
//		panic(err) // handle error
//	}
func RegisterKMSContextWrapWithAnyCMK(registry *CryptoRegistry, apiClient KmsAPIClient) error {
	if registry == nil {
		return errNilCryptoRegistry
	}
	return registry.AddWrap(KMSContextWrap, newKMSContextWrapEntryWithAnyCMK(apiClient))
}

// newKMSContextWrapEntryWithCMK builds returns a new kms+context key provider and its decrypt handler.
// The returned handler will be configured to calls KMS Decrypt API without specifying a specific KMS CMK.
func newKMSContextWrapEntryWithCMK(apiClient KmsAPIClient, cmkID string) WrapEntry {
	// These values are read only making them thread safe
	kp := &kmsContextKeyHandler{
		apiClient: apiClient,
		cmkID:     &cmkID,
	}

	return kp.decryptHandler
}

// newKMSContextWrapEntryWithAnyCMK builds returns a new kms+context key provider and its decrypt handler.
// The returned handler will be configured to calls KMS Decrypt API without specifying a specific KMS CMK.
func newKMSContextWrapEntryWithAnyCMK(apiClient KmsAPIClient) WrapEntry {
	// These values are read only making them thread safe
	kp := &kmsContextKeyHandler{
		apiClient: apiClient,
	}

	return kp.decryptHandler
}

// kmsContextKeyHandler wraps the kmsKeyHandler to explicitly make this type incompatible with the v1 client
// by not exposing the old interface implementations.
type kmsContextKeyHandler struct {
	apiClient KmsAPIClient
	cmkID     *string

	CipherData
}

func (kp *kmsContextKeyHandler) isAWSFixture() bool {
	return true
}

func newKMSContextKeyHandler(apiClient KmsAPIClient, cmkID string, matdesc MaterialDescription) *kmsContextKeyHandler {
	kp := &kmsContextKeyHandler{
		apiClient: apiClient,
		cmkID:     &cmkID,
	}

	if matdesc == nil {
		matdesc = MaterialDescription{}
	}

	kp.CipherData.WrapAlgorithm = KMSContextWrap
	kp.CipherData.MaterialDescription = matdesc

	return kp
}

func (kp *kmsContextKeyHandler) GenerateCipherDataWithCEKAlg(ctx context.Context, keySize int, ivSize int, cekAlgorithm string) (CipherData, error) {
	cd := kp.CipherData.Clone()

	if len(cekAlgorithm) == 0 {
		return CipherData{}, fmt.Errorf("cek algorithm identifier must not be empty")
	}

	if _, ok := cd.MaterialDescription[kmsAWSCEKContextKey]; ok {
		return CipherData{}, fmt.Errorf(kmsReservedKeyConflictErrMsg, kmsAWSCEKContextKey)
	}
	cd.MaterialDescription[kmsAWSCEKContextKey] = cekAlgorithm

	out, err := kp.apiClient.GenerateDataKey(ctx,
		&kms.GenerateDataKeyInput{
			EncryptionContext: cd.MaterialDescription,
			KeyId:             kp.cmkID,
			KeySpec:           types.DataKeySpecAes256,
		})
	if err != nil {
		return CipherData{}, err
	}

	iv, err := generateBytes(ivSize)
	if err != nil {
		return CipherData{}, err
	}

	cd.Key = out.Plaintext
	cd.IV = iv
	cd.EncryptedKey = out.CiphertextBlob

	return cd, nil
}

// decryptHandler initializes a KMS keyprovider with a material description. This
// is used with Decrypting kms content, due to the cmkID being in the material description.
func (kp kmsContextKeyHandler) decryptHandler(env Envelope) (CipherDataDecrypter, error) {
	if env.WrapAlg != KMSContextWrap {
		return nil, fmt.Errorf("%s value `%s` did not match the expected algorithm `%s` for this handler", cekAlgorithmHeader, env.WrapAlg, KMSContextWrap)
	}

	m := MaterialDescription{}
	err := m.decodeDescription([]byte(env.MatDesc))
	if err != nil {
		return nil, err
	}

	if v, ok := m[kmsAWSCEKContextKey]; !ok {
		return nil, fmt.Errorf("required key %v is missing from encryption context", kmsAWSCEKContextKey)
	} else if v != env.CEKAlg {
		return nil, fmt.Errorf(kmsMismatchCEKAlg)
	}

	kp.MaterialDescription = m
	kp.WrapAlgorithm = KMSContextWrap

	return &kp, nil
}

// DecryptKey makes a call to KMS to decrypt the key.
func (kp *kmsContextKeyHandler) DecryptKey(key []byte) ([]byte, error) {
	return kp.DecryptKeyWithContext(context.Background(), key)
}

// DecryptKeyWithContext makes a call to KMS to decrypt the key with request context.
func (kp *kmsContextKeyHandler) DecryptKeyWithContext(ctx context.Context, key []byte) ([]byte, error) {
	out, err := kp.apiClient.Decrypt(ctx,
		&kms.DecryptInput{
			KeyId:             kp.cmkID, // will be nil and not serialized if created with the AnyCMK constructor
			EncryptionContext: kp.MaterialDescription,
			CiphertextBlob:    key,
			GrantTokens:       []string{},
		})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

var (
	_ CipherDataGeneratorWithCEKAlg  = (*kmsContextKeyHandler)(nil)
	_ CipherDataDecrypter            = (*kmsContextKeyHandler)(nil)
	_ CipherDataDecrypterWithContext = (*kmsContextKeyHandler)(nil)
	_ awsFixture                     = (*kmsContextKeyHandler)(nil)
)
