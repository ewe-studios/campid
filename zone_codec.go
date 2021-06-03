package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackZoneCodec implements the ZoneCodec interface for using
// the MsgPack Codec.
type MsgPackZoneCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackZoneCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackZoneCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonZoneCodec implements the ZoneCodec interface for using
// the Json Codec.
type JsonZoneCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonZoneCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonZoneCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobZoneCodec implements the ZoneCodec interface for using
// the gob Codec.
type GobZoneCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobZoneCodec) Encode(w io.Writer, s Zone) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobZoneCodec) Decode(r io.Reader) (Zone, error) {
	var s Zone
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
