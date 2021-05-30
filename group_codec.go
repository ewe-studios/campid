package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackGroupCodec implements the GroupCodec interface for using
// the MsgPack Codec.
type MsgPackGroupCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackGroupCodec) Encode(w io.Writer, s Group) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonGroupCodec implements the GroupCodec interface for using
// the Json Codec.
type JsonGroupCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonGroupCodec) Encode(w io.Writer, s Group) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobGroupCodec implements the GroupCodec interface for using
// the gob Codec.
type GobGroupCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobGroupCodec) Encode(w io.Writer, s Group) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobGroupCodec) Decode(r io.Reader) (Group, error) {
	var s Group
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
