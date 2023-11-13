package materials

const (
	gcmKeySize       = 32
	gcmNonceSize     = 12
	defaultAlgorithm = "internal.AESGCMNoPadding"
)

type DecryptionMaterials struct {
	DataKey             DataKey
	ContentIV           []byte //base64 decoded content IV
	MaterialDescription MaterialDescription
	ContentAlgorithm    string
	TagLength           string
}

func NewDecryptionMaterials(req DecryptMaterialsRequest) (*DecryptionMaterials, error) {

	//cipherKey []byte, iv []byte, matDesc string,
	//	keyringAlg string, cekAlg string, tagLength string

	materialDescription := MaterialDescription{}
	err := materialDescription.DecodeDescription([]byte(req.MatDesc))
	if err != nil {
		return nil, err
	}
	dataKey := DataKey{
		KeyMaterial:      nil,
		EncryptedDataKey: req.CipherKey,
		DataKeyAlgorithm: req.KeyringAlg,
	}

	return &DecryptionMaterials{
		DataKey:             dataKey,
		ContentIV:           req.Iv,
		MaterialDescription: materialDescription,
		ContentAlgorithm:    req.CekAlg,
		TagLength:           req.TagLength,
	}, nil
}

type DataKey struct {
	KeyMaterial      []byte
	EncryptedDataKey []byte
	DataKeyAlgorithm string
}

type EncryptionMaterials struct {
	gcmKeySize        int
	gcmNonceSize      int
	algorithm         string
	encryptionContext map[string]string
}

func NewEncryptionMaterials() *EncryptionMaterials {
	return &EncryptionMaterials{
		gcmKeySize:        gcmKeySize,
		gcmNonceSize:      gcmNonceSize,
		algorithm:         defaultAlgorithm,
		encryptionContext: map[string]string{},
	}
}

// CryptographicMaterials is used for content encryption. It is used for storing the
// metadata of the encrypted content.
type CryptographicMaterials struct {
	Key                 []byte
	IV                  []byte
	KeyringAlgorithm    string
	CEKAlgorithm        string
	TagLength           string
	MaterialDescription MaterialDescription
	// EncryptedKey should be populated when calling GenerateCipherData
	EncryptedKey []byte
}
