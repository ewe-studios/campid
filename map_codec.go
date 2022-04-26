package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

type MapCodec interface {
	Decode(r io.Reader) (map[string]string, error)
	Encode(w io.Writer, c map[string]string) error
}

// MsgPackMapCodec implements the MapCodec interface for using
// the MsgPack Codec.
type MsgPackMapCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackMapCodec) Encode(w io.Writer, s map[string]string) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonMapCodec implements the MapCodec interface for using
// the Json Codec.
type JsonMapCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonMapCodec) Encode(w io.Writer, s map[string]string) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobMapCodec implements the MapCodec interface for using
// the gob Codec.
type GobMapCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobMapCodec) Encode(w io.Writer, s map[string]string) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobMapCodec) Decode(r io.Reader) (map[string]string, error) {
	var s map[string]string
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
