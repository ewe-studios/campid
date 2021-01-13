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
	if len(s.IP) != 0 {
		encoder.String("ip", s.IP.String())
	}

	encoder.String("method", s.Method)
	encoder.String("user", s.UserId)
	encoder.Int64("created", s.Created.Unix())
	encoder.Int64("updated", s.Updated.Unix())
	encoder.Int64("expiring", s.Expires.Unix())
	encoder.Int64("expiring_nano", s.Expires.UnixNano())

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
	if len(s.IP) != 0 {
		encoder.String("ip", s.IP.String())
	}

	encoder.ObjectFor("agent", func(encoder npkg.ObjectEncoder) {
		encoder.String("version", s.Agent.Version.String())
		encoder.String("type_name", s.Agent.Type.String())

		encoder.Int("security", int(s.Agent.Security))
		encoder.String("security_name", s.Agent.Security.String())

		encoder.Bool("mobile", s.Agent.Mobile)
		encoder.Bool("tablet", s.Agent.Tablet)

		encoder.String("os", s.Agent.OS)
		encoder.String("name", s.Agent.Name)
		encoder.Int("type", int(s.Agent.Type))
		encoder.String("browser", s.Agent.Browser)
		encoder.String("original", s.Agent.Original)

		if s.Agent.URL != nil {
			encoder.String("url", s.Agent.URL.String())
		}
	})

	encoder.String("method", s.Method)
	encoder.String("method", s.Method)
	encoder.String("user", s.UserId)
	encoder.Int64("created", s.Created.Unix())
	encoder.Int64("updated", s.Updated.Unix())
	encoder.Int64("expiring", s.Expires.Unix())
	encoder.Int64("expiring_nano", s.Expires.UnixNano())
	encoder.Object("meta", npkg.EncodableStringMap(s.Meta))
	return nil
}
