package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackSessionCodec implements the ZoneCodec interface for using
// the MsgPack Codec.
type MsgPackSessionCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackSessionCodec) Encode(w io.Writer, s *Zone) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackSessionCodec) Decode(r io.Reader) (*Zone, error) {
	var s Zone
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return &s, nerror.WrapOnly(err)
	}
	return &s, nil
}

// JsonSessionCodec implements the ZoneCodec interface for using
// the Json Codec.
type JsonSessionCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonSessionCodec) Encode(w io.Writer, s *Zone) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonSessionCodec) Decode(r io.Reader) (*Zone, error) {
	var s Zone
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return &s, nerror.WrapOnly(err)
	}
	return &s, nil
}

// GobSessionCodec implements the ZoneCodec interface for using
// the gob Codec.
type GobSessionCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobSessionCodec) Encode(w io.Writer, s *Zone) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobSessionCodec) Decode(r io.Reader) (*Zone, error) {
	var s Zone
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return &s, nerror.WrapOnly(err)
	}
	return &s, nil
}
