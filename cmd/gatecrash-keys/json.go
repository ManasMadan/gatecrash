package main

import (
	"bytes"
	"encoding/json"
)

// jsonIndent renders a value as indented JSON for printing.
func jsonIndent(value any) ([]byte, error) { return json.MarshalIndent(value, "", "  ") }

// jsonUnmarshalStrict decodes JSON, refusing unknown fields.
//
// Used when sniffing whether a file is a sealed manifest: a lenient decode would
// happily read a completely different JSON document as a Sealed with every field
// zero, and then report a confusing error two steps later.
func jsonUnmarshalStrict(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}
