package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

type DeviceCodec interface {
	Decode(r io.Reader) (Device, error)
	Encode(w io.Writer, c Device) error
}

// MsgPackDeviceCodec implements the DeviceCodec interface for using
// the MsgPack Codec.
type MsgPackDeviceCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackDeviceCodec) Encode(w io.Writer, s Device) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackDeviceCodec) Decode(r io.Reader) (Device, error) {
	var s Device
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonDeviceCodec implements the DeviceCodec interface for using
// the Json Codec.
type JsonDeviceCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonDeviceCodec) Encode(w io.Writer, s Device) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonDeviceCodec) Decode(r io.Reader) (Device, error) {
	var s Device
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobDeviceCodec implements the DeviceCodec interface for using
// the gob Codec.
type GobDeviceCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobDeviceCodec) Encode(w io.Writer, s Device) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobDeviceCodec) Decode(r io.Reader) (Device, error) {
	var s Device
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
