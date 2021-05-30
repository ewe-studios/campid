package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackUserCodec implements the UserCodec interface for using
// the MsgPack Codec.
type MsgPackUserCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackUserCodec) Encode(w io.Writer, s User) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackUserCodec) Decode(r io.Reader) (User, error) {
	var s User
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonUserCodec implements the UserCodec interface for using
// the Json Codec.
type JsonUserCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonUserCodec) Encode(w io.Writer, s User) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonUserCodec) Decode(r io.Reader) (User, error) {
	var s User
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobUserCodec implements the UserCodec interface for using
// the gob Codec.
type GobUserCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobUserCodec) Encode(w io.Writer, s User) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobUserCodec) Decode(r io.Reader) (User, error) {
	var s User
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
