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

func encodeMeta(reader lengthReader, cd CipherData) (Envelope, error) {
	iv := base64.StdEncoding.EncodeToString(cd.IV)
	key := base64.StdEncoding.EncodeToString(cd.EncryptedKey)

	contentLength := reader.GetContentLength()

	matdesc, err := cd.MaterialDescription.encodeDescription()
	if err != nil {
		return Envelope{}, err
	}

	return Envelope{
		CipherKey:             key,
		IV:                    iv,
		MatDesc:               string(matdesc),
		WrapAlg:               cd.WrapAlgorithm,
		CEKAlg:                cd.CEKAlgorithm,
		TagLen:                cd.TagLength,
		UnencryptedContentLen: strconv.FormatInt(contentLength, 10),
	}, nil
}

func wrapFromEnvelope(options DecryptionClientOptions, env Envelope) (CipherDataDecrypter, error) {
	f, ok := options.CryptoRegistry.GetWrap(env.WrapAlg)
	if !ok || f == nil {
		return nil, &smithy.GenericAPIError{
			Code:    "InvalidWrapAlgorithmError",
			Message: "wrap algorithm isn't supported, " + env.WrapAlg,
			Fault:   smithy.FaultClient,
		}
	}
	return f(env)
}

func cekFromEnvelope(ctx context.Context, options DecryptionClientOptions, env Envelope, decrypter CipherDataDecrypter) (ContentCipher, error) {
	f, ok := options.CryptoRegistry.GetCEK(env.CEKAlg)
	if !ok || f == nil {
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

	cd := CipherData{
		Key:          key,
		IV:           iv,
		CEKAlgorithm: env.CEKAlg,
		Padder:       getPadder(options, env.CEKAlg),
	}
	return f(cd)
}

// getPadder will return an unpadder with checking the cek algorithm specific padder.
// If there wasn't a cek algorithm specific padder, we check the padder itself.
// We return a no unpadder, if no unpadder was found. This means any customization
// either contained padding within the cipher implementation, and to maintain
// backwards compatibility we will simply not unpad anything.
func getPadder(options DecryptionClientOptions, cekAlg string) Padder {
	padder, ok := options.CryptoRegistry.GetPadder(cekAlg)
	if !ok {
		padder, ok = options.CryptoRegistry.GetPadder(cekAlg[strings.LastIndex(cekAlg, "/")+1:])
		if !ok {
			return NoPadder
		}
	}
	return padder
}

func contentCipherFromEnvelope(ctx context.Context, options DecryptionClientOptions, env Envelope) (ContentCipher, error) {
	wrap, err := wrapFromEnvelope(options, env)
	if err != nil {
		return nil, err
	}

	return cekFromEnvelope(ctx, options, env, wrap)
}
