package materials

import (
	"encoding/json"
)

// MaterialDescription is used to identify how and what master
// key has been used.
type MaterialDescription map[string]string

// Clone returns a copy of the MaterialDescription
func (md MaterialDescription) Clone() (clone MaterialDescription) {
	if md == nil {
		return nil
	}
	clone = make(MaterialDescription, len(md))
	for k, v := range md {
		clone[k] = v
	}
	return clone
}

func (md *MaterialDescription) EncodeDescription() ([]byte, error) {
	v, err := json.Marshal(&md)
	return v, err
}

func (md *MaterialDescription) DecodeDescription(b []byte) error {
	return json.Unmarshal(b, &md)
}
