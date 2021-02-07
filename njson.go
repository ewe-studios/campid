package campid

import (
	"github.com/influx6/npkg"
	"github.com/influx6/npkg/nerror"
)

type JSONSession struct {
	*Session
}

// EncodeForCookie encodes giving session to npkg.ObjectEncoder for
// delivery to the client.
func (s *JSONSession) EncodeForCookie(encoder npkg.ObjectEncoder) error {
	if err := s.Validate(); err != nil {
		return nerror.WrapOnly(err)
	}

	encoder.String("id", s.Id)

	encoder.String("method", s.Method)
	encoder.String("user", s.UserId)
	encoder.Int64("created", s.Created.Unix())
	encoder.Int64("updated", s.Updated.Unix())

	if s.Meta != nil && len(s.Meta) != 0 {
		encoder.Object("meta", npkg.EncodableStringMap(s.Meta))
	}
	return encoder.Err()
}

// EncodeObject implements the npkg.EncodableObject interface.
func (s *JSONSession) EncodeObject(encoder npkg.ObjectEncoder) error {
	if err := s.Validate(); err != nil {
		return nerror.WrapOnly(err)
	}

	encoder.String("id", s.Id)

	encoder.String("method", s.Method)
	encoder.String("method", s.Method)
	encoder.String("user", s.UserId)
	encoder.Int64("created", s.Created.Unix())
	encoder.Int64("updated", s.Updated.Unix())
	encoder.Object("meta", npkg.EncodableStringMap(s.Meta))
	return nil
}
