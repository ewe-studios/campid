package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackSessionCodec implements the ZoneCodec interface for using
// the MsgPack Codec.
type MsgPackSessionCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackSessionCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackSessionCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonSessionCodec implements the ZoneCodec interface for using
// the Json Codec.
type JsonSessionCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonSessionCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonSessionCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobSessionCodec implements the ZoneCodec interface for using
// the gob Codec.
type GobSessionCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobSessionCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobSessionCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
