package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackGroupCodec implements the GroupCodec interface for using
// the MsgPack Codec.
type MsgPackGroupCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackGroupCodec) Encode(w io.Writer, s Group) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonGroupCodec implements the GroupCodec interface for using
// the Json Codec.
type JsonGroupCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonGroupCodec) Encode(w io.Writer, s Group) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobGroupCodec implements the GroupCodec interface for using
// the gob Codec.
type GobGroupCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobGroupCodec) Encode(w io.Writer, s Group) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
