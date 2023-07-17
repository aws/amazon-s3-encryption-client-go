package s3crypto_test

import (
	"io"
	"strings"
	"testing"

	"github.com/awslabs/aws-sdk-go-s3-crypto"
)

func TestCryptoReadCloserRead(t *testing.T) {
	expectedStr := "HELLO WORLD "
	str := strings.NewReader(expectedStr)
	rc := &s3crypto.CryptoReadCloser{Body: io.NopCloser(str), Decrypter: str}

	b, err := io.ReadAll(rc)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if expectedStr != string(b) {
		t.Errorf("expected %s, but received %s", expectedStr, string(b))
	}
}

func TestCryptoReadCloserClose(t *testing.T) {
	data := "HELLO WORLD "
	expectedStr := ""

	str := strings.NewReader(data)
	rc := &s3crypto.CryptoReadCloser{Body: io.NopCloser(str), Decrypter: str}
	rc.Close()

	b, err := io.ReadAll(rc)
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if expectedStr != string(b) {
		t.Errorf("expected %s, but received %s", expectedStr, string(b))
	}
}
