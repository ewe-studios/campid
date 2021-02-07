package campid

import (
	"io"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/influx6/npkg/nerror"
)

type EmailLogin struct {
	Email    string
	Password string
}

type UsernameLogin struct {
	Username string
	Password string
}

type Mail struct {
	Email       string
	BC          []string
	CC          []string
	Message     []byte
	Attachments map[string][]byte
	Files       map[string]io.ReadCloser
}

type Mailer interface {
	SendMail(mail *Mail) error
}

type Message struct {
	Phone       string
	CountryCode string
	AreaCode    string
	Message     []byte
}

type Telephone interface {
	SendText(msg *Message) error
}

func CreateIndexMappingForAll() (mapping.IndexMapping, error) {
	var userMapping, err = CreateUserDocumentMapping()
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var roleMapping, roleMappingErr = CreateDeviceDocumentMapping()
	if roleMappingErr != nil {
		return nil, nerror.WrapOnly(roleMappingErr)
	}

	var deviceMapping, deviceErr = CreateDeviceDocumentMapping()
	if deviceErr != nil {
		return nil, nerror.WrapOnly(deviceErr)
	}

	var groupMapping, groupMappingErr = CreateDeviceDocumentMapping()
	if groupMappingErr != nil {
		return nil, nerror.WrapOnly(groupMappingErr)
	}

	var sessionMapping, sessionMappingErr = CreateDeviceDocumentMapping()
	if sessionMappingErr != nil {
		return nil, nerror.WrapOnly(sessionMappingErr)
	}

	indexMapping := bleve.NewIndexMapping()
	indexMapping.AddDocumentMapping("User", userMapping)
	indexMapping.AddDocumentMapping("Device", deviceMapping)
	indexMapping.AddDocumentMapping("Role", roleMapping)
	indexMapping.AddDocumentMapping("Group", groupMapping)
	indexMapping.AddDocumentMapping("Session", sessionMapping)
	return indexMapping, nil
}
