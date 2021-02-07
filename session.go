package campid

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/v2/analysis/lang/en"
	"github.com/blevesearch/bleve/v2/mapping"

	"github.com/influx6/npkg/nstorage"
	openTracing "github.com/opentracing/opentracing-go"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
)

var (
	bufferPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 512))
		},
	}
)

func CreateSessionDocumentMapping() (*mapping.DocumentMapping, error) {
	var sessionMapping = bleve.NewDocumentMapping()

	var englishTextField = bleve.NewTextFieldMapping()
	englishTextField.Analyzer = en.AnalyzerName

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	var dateTimeField = bleve.NewDateTimeFieldMapping()
	dateTimeField.Analyzer = keyword.Name

	sessionMapping.AddFieldMappingsAt("Created", dateTimeField)
	sessionMapping.AddFieldMappingsAt("Updated", dateTimeField)

	sessionMapping.AddFieldMappingsAt("IP", textField)
	sessionMapping.AddFieldMappingsAt("Id", textField)
	sessionMapping.AddFieldMappingsAt("Method", textField)
	sessionMapping.AddFieldMappingsAt("CsrfToken", textField)
	sessionMapping.AddFieldMappingsAt("UserId", englishTextField)

	return sessionMapping, nil
}

type Session struct {
	CSrfToken string
	Created   time.Time
	Updated   time.Time
	Id        string
	Method    string
	UserId    string
	Meta      map[string]string
}

// Validate returns an error if giving session was invalid.
func (s *Session) Validate() error {
	if s.Created.IsZero() {
		return nerror.New("session.Created has no created time stamp")
	}
	if s.Updated.IsZero() {
		return nerror.New("session.Updated has no updated time stamp")
	}
	if len(s.CSrfToken) == 0 {
		return nerror.New("session.CSrfToken must have a valid value")
	}
	if len(s.Id) == 0 {
		return nerror.New("session.ID must have a valid value")
	}
	if len(s.UserId) == 0 {
		return nerror.New("session.User must have a valid value")
	}
	return nil
}

// SessionCodec exposes an interface which combines the SessionEncoder and
// SessionDecoder interfaces.
type SessionCodec interface {
	Decode(r io.Reader) (*Session, error)
	Encode(w io.Writer, s *Session) error
}

// SessionStore implements a storage type for CRUD operations on
// campId.
type SessionStore struct {
	Codec SessionCodec
	Store nstorage.ExpirableStore
}

// NewSessionStore returns a new instance of a SessionStore.
func NewSessionStore(codec SessionCodec, store nstorage.ExpirableStore) *SessionStore {
	return &SessionStore{
		Codec: codec,
		Store: store,
	}
}

// Save adds giving session into underline Store.
//
// It sets the session to expire within the storage based on
// the giving session's expiration duration.
//
// Save calculates the ttl by subtracting the Session.Created value from
// the Session.Expires value.
func (s *SessionStore) Save(ctx context.Context, se *Session) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if err := se.Validate(); err != nil {
		return nerror.Wrap(err, "Session failed validation")
	}

	var content = bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(content)
	content.Reset()

	if err := s.Codec.Encode(content, se); err != nil {
		return nerror.Wrap(err, "Failed to encode data")
	}

	var key = buildSessionKey(se.Id, se.UserId)

	if err := s.Store.Save(key, content.Bytes()); err != nil {
		return nerror.Wrap(err, "Failed to save encoded session")
	}
	return nil
}

// Update attempts to update existing session key within Store if
// still available.
//
// Update calculates the ttl by subtracting the Session.Updated value from
// the Session.Expires value.
func (s *SessionStore) Update(ctx context.Context, se *Session) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	if err := se.Validate(); err != nil {
		return nerror.Wrap(err, "Session failed validation")
	}

	var content = bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(content)
	content.Reset()

	if err := s.Codec.Encode(content, se); err != nil {
		return nerror.Wrap(err, "Failed to encode data")
	}

	var key = buildSessionKey(se.Id, se.UserId)
	if err := s.Store.Update(key, content.Bytes()); err != nil {
		return nerror.Wrap(err, "Failed to update encoded session")
	}
	return nil
}

// GetAll returns all sessions stored within Store.
func (s *SessionStore) GetAll(ctx context.Context) ([]Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var sessions []Session
	var err = s.Store.Each(func(content []byte, key string) error {
		var reader = bytes.NewBuffer(content)
		var session, decodeErr = s.Codec.Decode(reader)
		if decodeErr != nil {
			return nerror.WrapOnly(decodeErr)
		}
		sessions = append(sessions, *session)
		return nil
	})
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return sessions, nil
}

// GetOneForUser will return a list of all found sessions data from the underline datastore.
func (s *SessionStore) GetOneForUser(ctx context.Context, userId string) (*Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var targetPrefix = buildSessionKey("*", userId)
	var sessionKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nil, nerror.WrapOnly(getKeysErr)
	}

	var sessionDataList, getDataErr = s.Store.GetAnyKeys(sessionKeys...)
	if getDataErr != nil {
		return nil, nerror.WrapOnly(getDataErr)
	}

	if len(sessionDataList) == 0 {
		return nil, nerror.New("has no sessions")
	}

	var reader = bytes.NewBuffer(sessionDataList[0])
	var session, decodeErr = s.Codec.Decode(reader)
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}
	return session, nil
}

// GetAllForUser will return a list of all found sessions data from the underline datastore.
func (s *SessionStore) GetAllForUser(ctx context.Context, userId string) ([]Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var targetPrefix = buildSessionKey("*", userId)
	var sessionKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nil, nerror.WrapOnly(getKeysErr)
	}

	var sessionDataList, getDataErr = s.Store.GetAnyKeys(sessionKeys...)
	if getDataErr != nil {
		return nil, nerror.WrapOnly(getDataErr)
	}

	if len(sessionDataList) == 0 {
		return nil, nerror.New("has no sessions")
	}

	var sessions = make([]Session, 0, len(sessionDataList))
	for _, sessionData := range sessionDataList {
		if len(sessionData) == 0 {
			continue
		}
		var reader = bytes.NewBuffer(sessionData)
		var session, decodeErr = s.Codec.Decode(reader)
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}
		sessions = append(sessions, *session)
	}
	return sessions, nil
}

func (s *SessionStore) Has(ctx context.Context, sid string, userId string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildSessionKey(sid, userId)

	var hasSession, err = s.Store.Exists(key)
	if err != nil {
		return false, nerror.WrapOnly(err)
	}
	return hasSession, nil
}

// GetByUser retrieves giving session from Store based on the provided
// session user value.
func (s *SessionStore) GetById(ctx context.Context, sid string, userId string) (*Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildSessionKey(sid, userId)

	var sessionBytes, err = s.Store.Get(key)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var session *Session
	var reader = bytes.NewReader(sessionBytes)
	if session, err = s.Codec.Decode(reader); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return session, nil
}

// Remove removes underline session if still present from underline Store.
func (s *SessionStore) Remove(ctx context.Context, sid string, userId string) (*Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildSessionKey(sid, userId)

	var session *Session
	var sessionBytes, err = s.Store.Remove(key)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var reader = bytes.NewReader(sessionBytes)
	if session, err = s.Codec.Decode(reader); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return session, nil
}

func (s *SessionStore) RemoveAllForUser(ctx context.Context, userId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var targetPrefix = buildSessionKey("*", userId)
	var sessionKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nerror.WrapOnly(getKeysErr)
	}

	if removeErr := s.Store.RemoveKeys(sessionKeys...); removeErr != nil {
		return nerror.WrapOnly(removeErr)
	}
	return nil
}

func buildSessionKey(sessionId string, userId string) string {
	return strings.Join([]string{userId, sessionId}, dot)
}
