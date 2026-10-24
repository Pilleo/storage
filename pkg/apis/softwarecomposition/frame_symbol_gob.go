package softwarecomposition

import (
	"encoding/json"
	"errors"
)

// GobEncode implements gob.GobEncoder without flattening present-zero optional scalars.
func (symbol FrameSymbol) GobEncode() ([]byte, error) {
	return json.Marshal(symbol)
}

// GobDecode implements gob.GobDecoder, replacing the receiver only after a valid payload.
func (symbol *FrameSymbol) GobDecode(payload []byte) error {
	var decoded *FrameSymbol
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return err
	}
	if decoded == nil {
		return errors.New("frame symbol gob payload must be an object")
	}
	*symbol = *decoded
	return nil
}
