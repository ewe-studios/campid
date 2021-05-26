package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackNewUserCodec implements the NewUserCodec interface for using
// the MsgPack Codec.
type MsgPackNewUserCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackNewUserCodec) Encode(w io.Writer, s NewUser) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonNewUserCodec implements the NewUserCodec interface for using
// the Json Codec.
type JsonNewUserCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonNewUserCodec) Encode(w io.Writer, s NewUser) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobNewUserCodec implements the NewUserCodec interface for using
// the gob Codec.
type GobNewUserCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobNewUserCodec) Encode(w io.Writer, s NewUser) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
