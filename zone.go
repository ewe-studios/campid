package campid

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/influx6/npkg/nxid"

	"github.com/ewe-studios/sabuhp"

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

func CreateZoneDocumentMapping() (*mapping.DocumentMapping, error) {
	var zoneMapping = bleve.NewDocumentMapping()

	var englishTextField = bleve.NewTextFieldMapping()
	englishTextField.Analyzer = en.AnalyzerName

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	var dateTimeField = bleve.NewDateTimeFieldMapping()
	dateTimeField.Analyzer = keyword.Name

	zoneMapping.AddFieldMappingsAt("Created", dateTimeField)
	zoneMapping.AddFieldMappingsAt("Updated", dateTimeField)

	zoneMapping.AddFieldMappingsAt("IP", textField)
	zoneMapping.AddFieldMappingsAt("Id", textField)
	zoneMapping.AddFieldMappingsAt("Method", textField)
	zoneMapping.AddFieldMappingsAt("CsrfToken", textField)
	zoneMapping.AddFieldMappingsAt("UserId", englishTextField)

	return zoneMapping, nil
}

type Zone struct {
	CsrfMessage string
	Created     time.Time
	Updated     time.Time
	Id          string
	Method      string
	UserId      string
	Meta        map[string]string
}

// Validate returns an error if giving zone was invalid.
func (s *Zone) Validate() error {
	if s.Created.IsZero() {
		return nerror.New("zone.Created has no created time stamp")
	}
	if s.Updated.IsZero() {
		return nerror.New("zone.Updated has no updated time stamp")
	}
	if len(s.CsrfMessage) == 0 {
		return nerror.New("zone.CSrfToken must have a valid value")
	}
	if len(s.Id) == 0 {
		return nerror.New("zone.Id must have a valid value")
	}
	if len(s.UserId) == 0 {
		return nerror.New("zone.User must have a valid value")
	}
	return nil
}

// ZoneCodec exposes an interface which combines the ZoneEncoder and
// ZoneDecoder interfaces.
type ZoneCodec interface {
	Decode(r io.Reader) (Zone, error)
	Encode(w io.Writer, s Zone) error
}

// ZoneStore implements a storage type for CRUD operations on
// campId.
type ZoneStore struct {
	Codec ZoneCodec
	Store nstorage.ExpirableStore
}

// NewZoneStore returns a new instance of a ZoneStore.
func NewZoneStore(codec ZoneCodec, store nstorage.ExpirableStore) *ZoneStore {
	return &ZoneStore{
		Codec: codec,
		Store: store,
	}
}

// Save adds giving zone into underline Store.
//
// It sets the zone to expire within the storage based on
// the giving zone's expiration duration.
//
// Save calculates the ttl by subtracting the Zone.Created value from
// the Zone.Expires value.
func (s *ZoneStore) Save(ctx context.Context, se *Zone) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if err := se.Validate(); err != nil {
		return nerror.Wrap(err, "Zone failed validation")
	}

	var content = bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(content)
	content.Reset()

	if err := s.Codec.Encode(content, *se); err != nil {
		return nerror.Wrap(err, "Failed to encode data")
	}

	var key = buildZoneKey(se.Id, se.UserId)

	if err := s.Store.Save(key, content.Bytes()); err != nil {
		return nerror.Wrap(err, "Failed to save encoded zone")
	}
	return nil
}

// Update attempts to update existing zone key within Store if
// still available.
//
// Update calculates the ttl by subtracting the Zone.Updated value from
// the Zone.Expires value.
func (s *ZoneStore) Update(ctx context.Context, se *Zone) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	if err := se.Validate(); err != nil {
		return nerror.Wrap(err, "Zone failed validation")
	}

	var content = bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(content)
	content.Reset()

	if err := s.Codec.Encode(content, *se); err != nil {
		return nerror.Wrap(err, "Failed to encode data")
	}

	var key = buildZoneKey(se.Id, se.UserId)
	if err := s.Store.Update(key, content.Bytes()); err != nil {
		return nerror.Wrap(err, "Failed to update encoded zone")
	}
	return nil
}

// GetAll returns all zones stored within Store.
func (s *ZoneStore) GetAll(ctx context.Context) ([]Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var zones []Zone
	var err = s.Store.Each(func(content []byte, key string) error {
		var reader = bytes.NewBuffer(content)
		var zone, decodeErr = s.Codec.Decode(reader)
		if decodeErr != nil {
			return nerror.WrapOnly(decodeErr)
		}
		zones = append(zones, zone)
		return nil
	})
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return zones, nil
}

// GetForUserId will target zone found from store for userId.
func (s *ZoneStore) GetForUserId(ctx context.Context, userId string) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var targetPrefix = buildZoneKey("*", userId)
	var zoneKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nil, nerror.WrapOnly(getKeysErr)
	}

	var zoneDataList, getDataErr = s.Store.GetAnyKeys(zoneKeys...)
	if getDataErr != nil {
		return nil, nerror.WrapOnly(getDataErr)
	}

	if len(zoneDataList) == 0 {
		return nil, nerror.New("has no zones")
	}

	var reader = bytes.NewBuffer(zoneDataList[0])
	var zone, decodeErr = s.Codec.Decode(reader)
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}
	return &zone, nil
}

// GetAllForUser will return a list of all found zones data from the underline datastore.
func (s *ZoneStore) GetAllForUser(ctx context.Context, userId string) ([]Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var targetPrefix = buildZoneKey("*", userId)
	var zoneKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nil, nerror.WrapOnly(getKeysErr)
	}

	var zoneDataList, getDataErr = s.Store.GetAnyKeys(zoneKeys...)
	if getDataErr != nil {
		return nil, nerror.WrapOnly(getDataErr)
	}

	if len(zoneDataList) == 0 {
		return nil, nerror.New("has no zones")
	}

	var zones = make([]Zone, 0, len(zoneDataList))
	for _, zoneData := range zoneDataList {
		if len(zoneData) == 0 {
			continue
		}
		var reader = bytes.NewBuffer(zoneData)
		var zone, decodeErr = s.Codec.Decode(reader)
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}
		zones = append(zones, zone)
	}
	return zones, nil
}

func (s *ZoneStore) Has(ctx context.Context, sid string, userId string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildZoneKey(sid, userId)

	var hasZone, err = s.Store.Exists(key)
	if err != nil {
		return false, nerror.WrapOnly(err)
	}
	return hasZone, nil
}

// GetByZoneAndUserId retrieves giving zone from Store based on the provided
// zone db id value.
func (s *ZoneStore) GetByZoneAndUserId(ctx context.Context, zid string, userId string) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildZoneKey(zid, userId)

	var zoneBytes, err = s.Store.Get(key)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var zone Zone
	var reader = bytes.NewReader(zoneBytes)
	if zone, err = s.Codec.Decode(reader); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return &zone, nil
}

// Remove removes underline zone if still present from underline Store.
func (s *ZoneStore) Remove(ctx context.Context, zid string, userId string) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var key = buildZoneKey(zid, userId)

	var zone Zone
	var zoneBytes, err = s.Store.Remove(key)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var reader = bytes.NewReader(zoneBytes)
	if zone, err = s.Codec.Decode(reader); err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return &zone, nil
}

func (s *ZoneStore) RemoveAllForUser(ctx context.Context, userId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var targetPrefix = buildZoneKey("*", userId)
	var zoneKeys, getKeysErr = s.Store.EachKeyMatch(targetPrefix)
	if getKeysErr != nil {
		return nerror.WrapOnly(getKeysErr)
	}

	if removeErr := s.Store.RemoveKeys(zoneKeys...); removeErr != nil {
		return nerror.WrapOnly(removeErr)
	}
	return nil
}

func buildZoneKey(zoneId string, userId string) string {
	return strings.Join([]string{userId, zoneId}, dot)
}

type ZoneService struct {
	Codec  Codec
	Store  *ZoneStore
	Topics sabuhp.TopicPartial
}

func (cs *ZoneService) Register(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(CreateZoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateZone))
	bus.Group(UpdateZoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.UpdateZone))
	bus.Group(DeleteZoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.RemoveUserZone))
}

func (cs *ZoneService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var records, getAllErr = cs.Store.GetAll(ctx)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, records); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *ZoneService) GetZone(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var zoneId = msg.Params.Get("zoneId")
	if len(zoneId) == 0 {
		var getAllErr = nerror.New("zoneId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetByZoneAndUserId(ctx, zoneId, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *ZoneService) GetForUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetForUserId(ctx, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *ZoneService) GetAllForUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetAllForUser(ctx, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *ZoneService) RemoveAllForUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var removeAllErr = cs.Store.RemoveAllForUser(ctx, userId)
	if removeAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(removeAllErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	newCraftedReply.Params.Set("userId", userId)
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(ZoneDeletedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *ZoneService) RemoveUserZone(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var zoneId = msg.Params.Get("zoneId")
	if len(zoneId) == 0 {
		var getAllErr = nerror.New("zoneId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.Remove(ctx, zoneId, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.Params.Set("userId", userId)
	newCraftedReply.Params.Set("zoneId", zoneId)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(ZoneDeletedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *ZoneService) CreateZone(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Zone
	update.Id = nxid.New().String()

	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var updateErr = cs.Store.Save(ctx, &update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, update); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(ZoneCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *ZoneService) UpdateZone(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Zone
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var updateErr = cs.Store.Update(ctx, &update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, update); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(ZoneUpdatedTopic)
	tr.ToBoth(newCraftedReply)

	return nil
}
