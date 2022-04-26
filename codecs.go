package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

type Codec interface {
	Encode(w io.Writer, s interface{}) error
	Decode(w io.Reader, s interface{}) error
}

// MsgPackCodec implements the LoginCodec interface for using
// the MsgPack LoginCodec.
type MsgPackCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackCodec) Encode(w io.Writer, s interface{}) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackCodec) Decode(r io.Reader, s interface{}) error {
	if err := msgpack.NewDecoder(r).Decode(s); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

// JsonCodec implements the LoginCodec interface for using
// the Json LoginCodec.
type JsonCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonCodec) Encode(w io.Writer, s interface{}) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonCodec) Decode(r io.Reader, s interface{}) error {
	if err := json.NewDecoder(r).Decode(s); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

// GobCodec implements the LoginCodec interface for using
// the gob LoginCodec.
type GobCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobCodec) Encode(w io.Writer, s interface{}) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobCodec) Decode(r io.Reader, s interface{}) error {
	if err := gob.NewDecoder(r).Decode(s); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}
