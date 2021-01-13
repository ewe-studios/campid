package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackUserCodec implements the UserCodec interface for using
// the MsgPack codec.
type MsgPackUserCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackUserCodec) Encode(w io.Writer, s *User) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackUserCodec) Decode(r io.Reader) (*User, error) {
	var s User
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return &s, nil
}

// JsonUserCodec implements the UserCodec interface for using
// the Json codec.
type JsonUserCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonUserCodec) Encode(w io.Writer, s *User) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonUserCodec) Decode(r io.Reader) (*User, error) {
	var s User
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return &s, nil
}

// GobUserCodec implements the UserCodec interface for using
// the gob codec.
type GobUserCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobUserCodec) Encode(w io.Writer, s *User) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobUserCodec) Decode(r io.Reader) (*User, error) {
	var s User
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return &s, nil
}
