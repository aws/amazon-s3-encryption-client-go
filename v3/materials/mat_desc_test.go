// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package materials

import (
	"reflect"
	"testing"
)

func TestEncodeMaterialDescription(t *testing.T) {
	md := MaterialDescription{}
	md["foo"] = "bar"
	b, err := md.EncodeDescription()
	expected := `{"foo":"bar"}`
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if expected != string(b) {
		t.Errorf("expected %s, but received %s", expected, string(b))
	}
}
func TestDecodeMaterialDescription(t *testing.T) {
	md := MaterialDescription{}
	json := `{"foo":"bar"}`
	err := md.DecodeDescription([]byte(json))
	expected := MaterialDescription{
		"foo": "bar",
	}
	if err != nil {
		t.Errorf("expected no error, but received %v", err)
	}
	if !reflect.DeepEqual(expected, md) {
		t.Error("expected material description to be equivalent, but received otherwise")
	}
}

func TestMaterialDescription_Clone(t *testing.T) {
	tests := map[string]struct {
		md        MaterialDescription
		wantClone MaterialDescription
	}{
		"it handles nil": {
			md:        nil,
			wantClone: nil,
		},
		"it copies all values": {
			md: MaterialDescription{
				"key1": "value1",
				"key2": "value2",
			},
			wantClone: MaterialDescription{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if gotClone := tt.md.Clone(); !reflect.DeepEqual(gotClone, tt.wantClone) {
				t.Errorf("Clone() = %v, want %v", gotClone, tt.wantClone)
			}
		})
	}
}
