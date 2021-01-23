package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

type MapCodec interface {
	Decode(r io.Reader) (map[string]string, error)
	Encode(w io.Writer, c map[string]string) error
}

// MsgPackMapCodec implements the MapCodec interface for using
// the MsgPack Codec.
type MsgPackMapCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackMapCodec) Encode(w io.Writer, s map[string]string) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonMapCodec implements the MapCodec interface for using
// the Json Codec.
type JsonMapCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonMapCodec) Encode(w io.Writer, s map[string]string) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobMapCodec implements the MapCodec interface for using
// the gob Codec.
type GobMapCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobMapCodec) Encode(w io.Writer, s map[string]string) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return s, nil
}
