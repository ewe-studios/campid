package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackNewUserCodec implements the NewUserCodec interface for using
// the MsgPack Codec.
type MsgPackNewUserCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackNewUserCodec) Encode(w io.Writer, s NewUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonNewUserCodec implements the NewUserCodec interface for using
// the Json Codec.
type JsonNewUserCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonNewUserCodec) Encode(w io.Writer, s NewUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobNewUserCodec implements the NewUserCodec interface for using
// the gob Codec.
type GobNewUserCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobNewUserCodec) Encode(w io.Writer, s NewUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobNewUserCodec) Decode(r io.Reader) (NewUser, error) {
	var s NewUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
