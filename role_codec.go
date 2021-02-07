package campid

import (
	"encoding/gob"
	"encoding/json"
	"io"

	"github.com/influx6/npkg/nerror"
	"github.com/vmihailenco/msgpack/v5"
)

// MsgPackRoleCodec implements the RoleCodec interface for using
// the MsgPack Codec.
type MsgPackRoleCodec struct{}

// Encode encodes giving session using the internal MsgPack format.
// Returning provided data.
func (gb *MsgPackRoleCodec) Encode(w io.Writer, s Role) error {
	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *MsgPackRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// JsonRoleCodec implements the RoleCodec interface for using
// the Json Codec.
type JsonRoleCodec struct{}

// Encode encodes giving session using the internal Json format.
// Returning provided data.
func (gb *JsonRoleCodec) Encode(w io.Writer, s Role) error {
	if err := json.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *JsonRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}

// GobRoleCodec implements the RoleCodec interface for using
// the gob Codec.
type GobRoleCodec struct{}

// Encode encodes giving session using the internal gob format.
// Returning provided data.
func (gb *GobRoleCodec) Encode(w io.Writer, s Role) error {
	if err := gob.NewEncoder(w).Encode(s); err != nil {
		return nerror.Wrap(err, "Failed to encode giving session")
	}
	return nil
}

// Decode decodes giving data into provided session instance.
func (gb *GobRoleCodec) Decode(r io.Reader) (Role, error) {
	var s Role
	if err := gob.NewDecoder(r).Decode(&s); err != nil {
		return s, nerror.WrapOnly(err)
	}
	return s, nil
}
