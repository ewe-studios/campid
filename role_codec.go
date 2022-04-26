package campid

import (
	"io"

	"github.com/influx6/npkg/nerror"
)

// MsgPackRoleCodec implements the RoleCodec interface for using
// the MsgPack Codec.
type MsgPackRoleCodec struct {
	Codec MsgPackCodec
}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackRoleCodec) Encode(w io.Writer, s Role) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonRoleCodec implements the RoleCodec interface for using
// the Json Codec.
type JsonRoleCodec struct {
	Codec JsonCodec
}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonRoleCodec) Encode(w io.Writer, s Role) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *JsonRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobRoleCodec implements the RoleCodec interface for using
// the gob Codec.
type GobRoleCodec struct {
	Codec GobCodec
}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobRoleCodec) Encode(w io.Writer, s Role) error {
	return gb.Codec.Encode(w, s)
}

// Decode decodes giving data into provided session instance.
func (gb *GobRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	var err = gb.Codec.Decode(r, &s)
	if err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
