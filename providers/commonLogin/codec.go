package commonLogin

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackEmailLoginCodec implements the LoginCodec interface for using
// the MsgPack LoginCodec.
type MsgPackEmailLoginCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackEmailLoginCodec) Encode(w io.Writer, s Login) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonEmailLoginCodec implements the LoginCodec interface for using
// the Json LoginCodec.
type JsonEmailLoginCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonEmailLoginCodec) Encode(w io.Writer, s Login) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobEmailLoginCodec implements the LoginCodec interface for using
// the gob LoginCodec.
type GobEmailLoginCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobEmailLoginCodec) Encode(w io.Writer, s Login) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// MsgPackRefreshLoginCodec implements the LoginCodec interface for using
// the MsgPack LoginCodec.
type MsgPackRefreshLoginCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackRefreshLoginCodec) Encode(w io.Writer, s RefreshLogin) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackRefreshLoginCodec) Decode(r io.Reader) (RefreshLogin, error) {
	var s RefreshLogin
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonRefreshLoginCodec implements the LoginCodec interface for using
// the Json LoginCodec.
type JsonRefreshLoginCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonRefreshLoginCodec) Encode(w io.Writer, s RefreshLogin) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonRefreshLoginCodec) Decode(r io.Reader) (RefreshLogin, error) {
	var s RefreshLogin
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobRefreshLoginCodec implements the LoginCodec interface for using
// the gob LoginCodec.
type GobRefreshLoginCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobRefreshLoginCodec) Encode(w io.Writer, s RefreshLogin) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobRefreshLoginCodec) Decode(r io.Reader) (RefreshLogin, error) {
	var s RefreshLogin
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
