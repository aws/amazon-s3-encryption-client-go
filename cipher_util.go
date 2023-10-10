package s3crypto

import (
	"encoding/base64"
	"strconv"
)

// TODO: relocate this and above constants
func encodeMeta(reader lengthReader, cd CryptographicMaterials) (ObjectMetadata, error) {
	iv := base64.StdEncoding.EncodeToString(cd.IV)
	key := base64.StdEncoding.EncodeToString(cd.EncryptedKey)

	contentLength := reader.GetContentLength()

	matdesc, err := cd.MaterialDescription.encodeDescription()
	if err != nil {
		return ObjectMetadata{}, err
	}

	return ObjectMetadata{
		CipherKey:             key,
		IV:                    iv,
		MatDesc:               string(matdesc),
		KeyringAlg:            cd.KeyringAlgorithm,
		CEKAlg:                cd.CEKAlgorithm,
		TagLen:                cd.TagLength,
		UnencryptedContentLen: strconv.FormatInt(contentLength, 10),
	}, nil
}
