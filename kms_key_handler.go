package s3crypto

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

const (
	// KMSWrap is a constant used during decryption to build a KMS key handler.
	KMSWrap = "kms"
)

// kmsKeyHandler will make calls to KMS to get the masterkey
type kmsKeyHandler struct {
	apiClient KmsAPIClient
	cmkID     *string

	// useProvidedCMK is toggled when using `kms` key wrapper with V2 client
	useProvidedCMK bool

	CipherData
}

// newKMSWrapEntry builds returns a new KMS key provider and its decrypt handler.
func newKMSWrapEntry(apiClient KmsAPIClient) WrapEntry {
	kp := newKMSKeyHandler(apiClient)
	return kp.decryptHandler
}

// RegisterKMSWrapWithCMK registers the `kms` wrapping algorithm to the given WrapRegistry. The wrapper will be
// configured to call KMS Decrypt with the provided CMK.
//
// Example:
//
//	sess := session.Must(session.NewSession())
//	cr := s3crypto.NewCryptoRegistry()
//	if err := s3crypto.RegisterKMSWrapWithCMK(cr, kms.New(sess), "cmkId"); err != nil {
//		panic(err) // handle error
//	}
//
// deprecated: This feature is in maintenance mode, no new updates will be released. Please see https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html for more information.
func RegisterKMSWrapWithCMK(registry *CryptoRegistry, apiClient KmsAPIClient, cmkID string) error {
	if registry == nil {
		return errNilCryptoRegistry
	}
	return registry.AddWrap(KMSWrap, newKMSWrapEntryWithCMK(apiClient, cmkID))
}

// RegisterKMSWrapWithAnyCMK registers the `kms` wrapping algorithm to the given WrapRegistry. The wrapper will be
// configured to call KMS Decrypt without providing a CMK.
//
// Example:
//
//	sess := session.Must(session.NewSession())
//	cr := s3crypto.NewCryptoRegistry()
//	if err := s3crypto.RegisterKMSWrapWithAnyCMK(cr, kms.New(sess)); err != nil {
//		panic(err) // handle error
//	}
//
// deprecated: This feature is in maintenance mode, no new updates will be released. Please see https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html for more information.
func RegisterKMSWrapWithAnyCMK(registry *CryptoRegistry, apiClient KmsAPIClient) error {
	if registry == nil {
		return errNilCryptoRegistry
	}
	return registry.AddWrap(KMSWrap, newKMSWrapEntry(apiClient))
}

// newKMSWrapEntryWithCMK builds returns a new KMS key provider and its decrypt handler. The wrap entry will be configured
// to only attempt to decrypt the data key using the provided CMK.
func newKMSWrapEntryWithCMK(apiClient KmsAPIClient, cmkID string) WrapEntry {
	kp := newKMSKeyHandler(apiClient)
	kp.useProvidedCMK = true
	kp.cmkID = &cmkID
	return kp.decryptHandler
}

func newKMSKeyHandler(apiClient KmsAPIClient) *kmsKeyHandler {
	// These values are read only making them thread safe
	kp := &kmsKeyHandler{
		apiClient: apiClient,
	}

	return kp
}

// decryptHandler initializes a KMS keyprovider with a material description. This
// is used with Decrypting kms content, due to the cmkID being in the material description.
func (kp kmsKeyHandler) decryptHandler(env Envelope) (CipherDataDecrypter, error) {
	m := MaterialDescription{}
	err := m.decodeDescription([]byte(env.MatDesc))
	if err != nil {
		return nil, err
	}

	_, ok := m["kms_cmk_id"]
	if !ok {
		return nil, &smithy.GenericAPIError{
			Code:    "MissingCMKIDError",
			Message: "Material description is missing CMK ID",
		}
	}

	kp.CipherData.MaterialDescription = m
	kp.WrapAlgorithm = KMSWrap

	return &kp, nil
}

// DecryptKey makes a call to KMS to decrypt the key.
func (kp *kmsKeyHandler) DecryptKey(key []byte) ([]byte, error) {
	return kp.DecryptKeyWithContext(context.Background(), key)
}

// DecryptKeyWithContext makes a call to KMS to decrypt the key with request context.
func (kp *kmsKeyHandler) DecryptKeyWithContext(ctx context.Context, key []byte) ([]byte, error) {
	in := &kms.DecryptInput{
		EncryptionContext: kp.MaterialDescription,
		CiphertextBlob:    key,
		GrantTokens:       []string{},
	}

	// useProvidedCMK will be true if a constructor was used with the new V2 client
	if kp.useProvidedCMK {
		in.KeyId = kp.cmkID
	}

	out, err := kp.apiClient.Decrypt(ctx, in)
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// GenerateCipherData makes a call to KMS to generate a data key, Upon making
// the call, it also sets the encrypted key.
func (kp *kmsKeyHandler) GenerateCipherData(keySize, ivSize int) (CipherData, error) {
	return kp.GenerateCipherDataWithContext(context.Background(), keySize, ivSize)
}

// GenerateCipherDataWithContext makes a call to KMS to generate a data key,
// Upon making the call, it also sets the encrypted key.
func (kp *kmsKeyHandler) GenerateCipherDataWithContext(ctx context.Context, keySize, ivSize int) (CipherData, error) {
	cd := kp.CipherData.Clone()

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

func (kp kmsKeyHandler) isAWSFixture() bool {
	return true
}

var (
	_ CipherDataGenerator            = (*kmsKeyHandler)(nil)
	_ CipherDataGeneratorWithContext = (*kmsKeyHandler)(nil)
	_ CipherDataDecrypter            = (*kmsKeyHandler)(nil)
	_ CipherDataDecrypterWithContext = (*kmsKeyHandler)(nil)
	_ awsFixture                     = (*kmsKeyHandler)(nil)
)
