package campid

import (
	"bytes"
	"context"
	"net"
	"strings"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/v2/analysis/lang/en"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/search/query"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
	"xojoc.pw/useragent"
)

func CreateDeviceDocumentMapping() (*mapping.DocumentMapping, error) {
	var sessionMapping = bleve.NewDocumentMapping()

	var englishTextField = bleve.NewTextFieldMapping()
	englishTextField.Analyzer = en.AnalyzerName

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	var booleanField = bleve.NewBooleanFieldMapping()
	booleanField.Analyzer = keyword.Name

	var dateTimeField = bleve.NewDateTimeFieldMapping()
	booleanField.Analyzer = keyword.Name

	sessionMapping.AddFieldMappingsAt("Created", dateTimeField)
	sessionMapping.AddFieldMappingsAt("Updated", dateTimeField)
	sessionMapping.AddFieldMappingsAt("IsEnabled", booleanField)
	sessionMapping.AddFieldMappingsAt("IsTrusted", booleanField)

	var agentMapping = bleve.NewDocumentMapping()
	agentMapping.AddFieldMappingsAt("Browser", textField)
	agentMapping.AddFieldMappingsAt("OS", textField)
	agentMapping.AddFieldMappingsAt("Mobile", booleanField)
	agentMapping.AddFieldMappingsAt("Tablet", booleanField)

	sessionMapping.AddSubDocumentMapping("Agent", agentMapping)

	var locationMapping = bleve.NewDocumentMapping()
	agentMapping.AddFieldMappingsAt("Street", textField)
	agentMapping.AddFieldMappingsAt("City", textField)
	agentMapping.AddFieldMappingsAt("State", textField)
	agentMapping.AddFieldMappingsAt("Postal", textField)
	agentMapping.AddFieldMappingsAt("Country", textField)

	sessionMapping.AddSubDocumentMapping("Location", locationMapping)

	sessionMapping.AddFieldMappingsAt("IP", textField)
	sessionMapping.AddFieldMappingsAt("Id", textField)
	sessionMapping.AddFieldMappingsAt("FingerprintId", textField)
	sessionMapping.AddFieldMappingsAt("UserId", textField)
	sessionMapping.AddFieldMappingsAt("SessionId", textField)

	return sessionMapping, nil
}

type Agent struct {
	*useragent.UserAgent
	Browser string
}

func ParseAgent(agentString string) (*Agent, error) {
	var agentInfo = useragent.Parse(agentString)
	if agentInfo == nil {
		return nil, nerror.New("failed to parse agent")
	}
	return &Agent{
		Browser:   agentInfo.Name,
		UserAgent: agentInfo,
	}, nil
}

type Location struct {
	Street  string
	City    string
	State   string
	Postal  string
	Country string
}

type DeviceInfo struct {
	FingerprintId string
	UserId        string
	SessionId     string
	IP            net.IP
	Location      Location
	Agent         *Agent
	IsEnabled     bool
	IsTrusted     bool
}

type Device struct {
	IsEnabled     bool
	IsTrusted     bool
	FingerprintId string // fingerprint id or device id unique to device if available.
	Id            string
	UserId        string
	SessionId     string
	IP            string
	Location      Location
	Agent         *Agent
	Created       time.Time
	Updated       time.Time
}

func (d Device) Key() string {
	return strings.Join([]string{d.SessionId, d.Id}, dot)
}

type DeviceStore struct {
	Codec   DeviceCodec
	Indexer bleve.Index
	Store   nstorage.ExpirableStore
}

func NewDeviceStore(codec DeviceCodec, store nstorage.ExpirableStore, indexer bleve.Index) *DeviceStore {
	return &DeviceStore{
		Codec:   codec,
		Store:   store,
		Indexer: indexer,
	}
}

func (ds *DeviceStore) Update(
	ctx context.Context,
	d *Device,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var b strings.Builder
	var encodedErr = ds.Codec.Encode(&b, *d)
	if encodedErr != nil {
		return nil, nerror.WrapOnly(encodedErr)
	}

	if saveErr := ds.Store.Update(d.Key(), nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	if indexErr := ds.Indexer.Index(d.Key(), d); indexErr != nil {
		return nil, nerror.WrapOnly(indexErr)
	}

	return d, nil
}

func (ds *DeviceStore) Remove(ctx context.Context, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var _, removeIdErr = ds.Store.Remove(d.Key())
	if removeIdErr != nil {
		return nerror.WrapOnly(removeIdErr)
	}

	if indexDelErr := ds.Indexer.Delete(d.Key()); indexDelErr != nil {
		return nerror.WrapOnly(indexDelErr)
	}
	return nil
}

func (ds *DeviceStore) Create(
	ctx context.Context,
	info DeviceInfo,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = ds.GetDeviceWithIPAndCity(ctx, info.IP.String(), info.Location.City, info.FingerprintId)
	if getDeviceErr == nil {
		return device, nil
	}

	var d Device
	d.Id = nxid.New().String()
	d.Agent = info.Agent
	d.IsEnabled = info.IsEnabled
	d.IsTrusted = info.IsTrusted
	d.IP = info.IP.String()
	d.Location = info.Location
	d.UserId = info.UserId
	d.SessionId = info.SessionId
	d.FingerprintId = info.FingerprintId

	d.Created = time.Now()
	d.Updated = d.Created

	var b strings.Builder
	var encodedErr = ds.Codec.Encode(&b, d)
	if encodedErr != nil {
		return nil, nerror.WrapOnly(encodedErr)
	}

	if saveErr := ds.Store.Save(d.Key(), nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	if indexErr := ds.Indexer.Index(d.Key(), d); indexErr != nil {
		return nil, nerror.WrapOnly(indexErr)
	}

	return &d, nil
}

// RemoveAllDevicesForSessiond returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) RemoveAllDevicesForSessionId(ctx context.Context, sessionId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(sessionId) == 0 {
		return nerror.New("neither value can be empty").
			Add("sessionId", sessionId)
	}

	var userQuery = query.NewMatchQuery("SessionId: " + sessionId)
	var req = bleve.NewSearchRequest(userQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nerror.Wrap(searchErr, "searching for ip").
			Add("sessionId", sessionId)
	}

	if searchResult.Total == 0 {
		return nerror.New("not found")
	}

	var batchRemover = ds.Indexer.NewBatch()

	var devices = make([]string, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		devices[index] = matcher.ID
		batchRemover.Delete(matcher.ID)
	}

	if removeErr := ds.Store.RemoveKeys(devices...); removeErr != nil {
		return nerror.WrapOnly(removeErr)
	}

	if removeErr := ds.Indexer.Batch(batchRemover); removeErr != nil {
		return nerror.WrapOnly(removeErr)
	}

	return nil
}

// GetDeviceForSessionId returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetDeviceForSessionId(ctx context.Context, sessionId string, deviceId string) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(deviceId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("deviceId", deviceId).Add("sessionId", sessionId)
	}

	var idQuery = query.NewMatchQuery("Id: " + deviceId)
	var sessionQuery = query.NewMatchQuery("SessionId: " + sessionId)

	var queryList = []query.Query{sessionQuery, idQuery}
	var searchQuery = query.NewConjunctionQuery(queryList)
	var req = bleve.NewSearchRequest(searchQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for id").
			Add("deviceId", deviceId).Add("sessionId", sessionId)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var matcher = searchResult.Hits[0]
	var deviceData, getErr = ds.Store.Get(matcher.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr).Add("id", deviceId)
	}

	var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr).
			Add("deviceId", deviceId).Add("sessionId", sessionId)
	}

	return &decodedDevice, nil
}

// GetDeviceWithFingerprint returns found device matching fingerprintId.
func (ds *DeviceStore) GetDeviceWithFingerprint(ctx context.Context, fingerprintId string) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(fingerprintId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("fingerprintId", fingerprintId)
	}

	var fingerprintIdQuery = query.NewMatchQuery("FingerprintId: " + fingerprintId)
	var req = bleve.NewSearchRequest(fingerprintIdQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("fingerprintId", fingerprintId)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("fingerprintId", fingerprintId)
	}

	var matcher = searchResult.Hits[0]
	var deviceData, getErr = ds.Store.Get(matcher.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr).Add("fingerprintId", fingerprintId)
	}

	var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr).Add("fingerprintId", fingerprintId)
	}

	return &decodedDevice, nil
}

// GetDevice returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetDevice(ctx context.Context, id string) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(id) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("id", id)
	}

	var idQuery = query.NewMatchQuery("Id: " + id)
	var req = bleve.NewSearchRequest(idQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("id", id)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("id", id)
	}

	var matcher = searchResult.Hits[0]
	var deviceData, getErr = ds.Store.Get(matcher.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr).Add("id", id)
	}

	var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr).Add("id", id)
	}

	return &decodedDevice, nil
}

// GetAll returns all device records in store.
func (ds *DeviceStore) GetAll(ctx context.Context) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var count, countErr = ds.Store.Count()
	if countErr != nil {
		return nil, nerror.WrapOnly(countErr)
	}

	var devices = make([]Device, 0, count)
	if readErr := ds.Store.Each(func(data []byte, key string) error {
		var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(data))
		if decodeErr != nil {
			return nerror.WrapOnly(decodeErr).Add("key", key)
		}

		devices = append(devices, decodedDevice)
		return nil
	}); readErr != nil {
		return nil, nerror.WrapOnly(readErr)
	}

	return devices, nil
}

// GetAllDevicesForSessiond returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetAllDevicesForSessionId(ctx context.Context, sessionId string) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(sessionId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("sessionId", sessionId)
	}

	var userQuery = query.NewMatchQuery("SessionId: " + sessionId)
	var req = bleve.NewSearchRequest(userQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("sessionId", sessionId)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var devices = make([]Device, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = ds.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr).Add("sessionId", sessionId)
		}

		var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr).Add("sessionId", sessionId)
		}

		devices[index] = decodedDevice
	}

	return devices, nil
}

// GetAllDevicesForUserId returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetAllDevicesForUserId(ctx context.Context, userId string) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(userId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("userId", userId)
	}

	var userQuery = query.NewMatchQuery("UserId: " + userId)
	var req = bleve.NewSearchRequest(userQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("userId", userId)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var devices = make([]Device, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = ds.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr).Add("userId", userId)
		}

		var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr).Add("userId", userId)
		}

		devices[index] = decodedDevice
	}

	return devices, nil
}

// GetAllDevicesWithIPAndCity returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetAllDevicesWithIPAndCity(ctx context.Context, ip string, city string) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(ip) == 0 || len(city) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("city", city).Add("ip", ip)
	}

	var cityQuery = query.NewMatchQuery("Location.City: " + city)
	var ipQuery = query.NewMatchQuery("IP:" + escapeIP(ip))

	var queryList = []query.Query{ipQuery, cityQuery}
	var searchQuery = query.NewConjunctionQuery(queryList)
	var req = bleve.NewSearchRequest(searchQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("city", city).Add("ip", ip)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var devices = make([]Device, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = ds.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr)
		}

		var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}

		devices[index] = decodedDevice
	}

	return devices, nil
}

// GetDeviceWithIPAndCity returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetDeviceWithIPAndCity(ctx context.Context, ip string, city string, optionalFingerprintId string) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(ip) == 0 || len(city) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("city", city).Add("ip", ip)
	}

	var cityQuery = query.NewMatchQuery("Location.City: " + city)
	var ipQuery = query.NewMatchQuery("IP:" + escapeIP(ip))

	var queryList = []query.Query{ipQuery, cityQuery}
	if len(optionalFingerprintId) != 0 {
		var fingerprintIdQuery = query.NewMatchQuery("FingerprintId: " + optionalFingerprintId)
		queryList = append(queryList, fingerprintIdQuery)
	}

	var searchQuery = query.NewConjunctionQuery(queryList)
	var req = bleve.NewSearchRequest(searchQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("city", city).Add("ip", ip)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var firstMatch = searchResult.Hits[0]
	var deviceData, getErr = ds.Store.Get(firstMatch.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return &decodedDevice, nil
}

func (ds *DeviceStore) HasDeviceWithIPAndCity(ctx context.Context, ip string, city string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var cityQuery = query.NewMatchQuery("Location.City: " + city)
	var ipQuery = query.NewMatchQuery("IP:" + escapeIP(ip))

	var searchQuery = query.NewConjunctionQuery([]query.Query{ipQuery, cityQuery})
	var req = bleve.NewSearchRequest(searchQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for ip").
			Add("city", city).Add("ip", ip)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (ds *DeviceStore) HasStreet(ctx context.Context, street string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Street: " + street)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for ip").Add("street", street)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (ds *DeviceStore) HasIP(ctx context.Context, ip string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("IP: " + escapeIP(ip))
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for ip").Add("ip", ip)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func escapeIP(ip string) string {
	return strings.ReplaceAll(ip, ":", `\:`)
}
