// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"testing"
)

// Assert customS3Decoder doesn't panic if reading a tampered, invalid material description.
func TestCustomS3Decoder_TruncatedMultiByteReturnsError(t *testing.T) {
	cases := map[string]string{
		"mime 0x80":         "=?utf-8?B?gA==?=",
		"mime 0xff":         "=?utf-8?B?/w==?=",
		"mime abc+0xff":     "=?utf-8?B?YWJj/w==?=",
		"raw trailing 0xff": "abc\xff",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := customS3Decoder(in)
			if err == nil {
				t.Fatalf("expected a decode error for %q, got decoded=%q, err=nil", in, out)
			}
		})
	}
}

// Well-formed ASCII JSON material descriptions must decode unchanged.
func TestCustomS3Decoder_ValidJSONUnchanged(t *testing.T) {
	for _, in := range []string{`{"foo":"bar"}`, `{}`} {
		out, err := customS3Decoder(in)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", in, err)
		}
		if out != in {
			t.Fatalf("expected %q unchanged, got %q", in, out)
		}
	}
}
