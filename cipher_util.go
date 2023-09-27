package s3crypto

import (
	"context"
	"encoding/base64"
	"github.com/aws/smithy-go"
	"strconv"
	"strings"
)

// AESGCMNoPadding is the constant value that is used to specify
// the cek algorithm consiting of AES GCM with no padding.
const AESGCMNoPadding = "AES/GCM/NoPadding"

// AESCBC is the string constant that signifies the AES CBC algorithm cipher.
const AESCBC = "AES/CBC"

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

func keyringFromEnvelope(options EncryptionClientOptions, env ObjectMetadata) (CipherDataDecrypter, error) {
	f, ok := options.CryptographicMaterialsManager.GetKeyring(env.KeyringAlg)
	if !ok || f == nil {
		return nil, &smithy.GenericAPIError{
			Code:    "InvalidKeyringAlgorithmError",
			Message: "KeyringEntry algorithm isn't supported, " + env.KeyringAlg,
			Fault:   smithy.FaultClient,
		}
	}
	return f(env)
}

func cekFromEnvelope(ctx context.Context, options EncryptionClientOptions, env ObjectMetadata, decrypter CipherDataDecrypter) (ContentCipher, error) {
	registeredCek, ok := options.CryptographicMaterialsManager.GetCEK(env.CEKAlg)
	if !ok || registeredCek == nil {
		return nil, &smithy.GenericAPIError{
			Code:    "InvalidCEKAlgorithmError",
			Message: "cek algorithm isn't supported, " + env.CEKAlg,
			Fault:   smithy.FaultClient,
		}
	}

	key, err := base64.StdEncoding.DecodeString(env.CipherKey)
	if err != nil {
		return nil, err
	}

	iv, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, err
	}

	if d, ok := decrypter.(CipherDataDecrypterWithContext); ok {
		key, err = d.DecryptKeyWithContext(ctx, key)
	} else {
		key, err = decrypter.DecryptKey(key)
	}

	if err != nil {
		return nil, err
	}

	cd := CryptographicMaterials{
		Key:          key,
		IV:           iv,
		CEKAlgorithm: env.CEKAlg,
		Padder:       getPadder(options, env.CEKAlg),
	}
	return registeredCek(cd)
}

// getPadder will return an unpadder with checking the cek algorithm specific padder.
// If there wasn't a cek algorithm specific padder, we check the padder itself.
// We return a no unpadder, if no unpadder was found. This means any customization
// either contained padding within the cipher implementation, and to maintain
// backwards compatibility we will simply not unpad anything.
func getPadder(options EncryptionClientOptions, cekAlg string) Padder {
	padder, ok := options.CryptographicMaterialsManager.GetPadder(cekAlg)
	if !ok {
		padder, ok = options.CryptographicMaterialsManager.GetPadder(cekAlg[strings.LastIndex(cekAlg, "/")+1:])
		if !ok {
			return NoPadder
		}
	}
	return padder
}
