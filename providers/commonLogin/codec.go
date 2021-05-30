package commonLogin

import (
	"io"

	"github.com/ewe-studios/campid"

	"github.com/influx6/npkg/nerror"
)

// MsgPackRegisteredUserCodec implements the RegisteredUserCodec interface for using
// the MsgPack RegisteredUserCodec.
type MsgPackRegisteredUserCodec struct {
	Codec campid.MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackRegisteredUserCodec) Encode(w io.Writer, s RegisteredUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackRegisteredUserCodec) Decode(r io.Reader) (RegisteredUser, error) {
	var s RegisteredUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonRegisteredUserCodec implements the RegisteredUserCodec interface for using
// the Json RegisteredUserCodec.
type JsonRegisteredUserCodec struct {
	Codec campid.JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonRegisteredUserCodec) Encode(w io.Writer, s RegisteredUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonRegisteredUserCodec) Decode(r io.Reader) (RegisteredUser, error) {
	var s RegisteredUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobRegisteredUserCodec implements the RegisteredUserCodec interface for using
// the gob RegisteredUserCodec.
type GobRegisteredUserCodec struct {
	Codec campid.GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobRegisteredUserCodec) Encode(w io.Writer, s RegisteredUser) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobRegisteredUserCodec) Decode(r io.Reader) (RegisteredUser, error) {
	var s RegisteredUser
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// MsgPackEmailLoginCodec implements the LoginCodec interface for using
// the MsgPack LoginCodec.
type MsgPackEmailLoginCodec struct {
	Codec campid.MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackEmailLoginCodec) Encode(w io.Writer, s Login) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonEmailLoginCodec implements the LoginCodec interface for using
// the Json LoginCodec.
type JsonEmailLoginCodec struct {
	Codec campid.JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonEmailLoginCodec) Encode(w io.Writer, s Login) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobEmailLoginCodec implements the LoginCodec interface for using
// the gob LoginCodec.
type GobEmailLoginCodec struct {
	Codec campid.GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobEmailLoginCodec) Encode(w io.Writer, s Login) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobEmailLoginCodec) Decode(r io.Reader) (Login, error) {
	var s Login
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// MsgPackRefreshLoginCodec implements the LoginCodec interface for using
// the MsgPack LoginCodec.
type MsgPackRefreshLoginCodec struct {
	Codec campid.MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackRefreshLoginCodec) Encode(w io.Writer, s RefreshUserAccess) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackRefreshLoginCodec) Decode(r io.Reader) (RefreshUserAccess, error) {
	var s RefreshUserAccess
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonRefreshLoginCodec implements the LoginCodec interface for using
// the Json LoginCodec.
type JsonRefreshLoginCodec struct {
	Codec campid.JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonRefreshLoginCodec) Encode(w io.Writer, s RefreshUserAccess) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonRefreshLoginCodec) Decode(r io.Reader) (RefreshUserAccess, error) {
	var s RefreshUserAccess
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobRefreshLoginCodec implements the LoginCodec interface for using
// the gob LoginCodec.
type GobRefreshLoginCodec struct {
	Codec campid.GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobRefreshLoginCodec) Encode(w io.Writer, s RefreshUserAccess) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobRefreshLoginCodec) Decode(r io.Reader) (RefreshUserAccess, error) {
	var s RefreshUserAccess
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
