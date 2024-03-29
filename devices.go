package campid

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ewe-studios/sabuhp"

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
	sessionMapping.AddFieldMappingsAt("ZoneId", textField)

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
	ZoneId        string
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
	ZoneId        string
	IP            string
	Location      Location
	Agent         *Agent
	Created       time.Time
	Updated       time.Time
}

func (d Device) IsForUser(u *User) bool {
	if len(d.UserId) == 0 {
		return false
	}
	if u.Id == d.UserId {
		return true
	}
	return false
}

func (d Device) Key() string {
	return strings.Join([]string{d.ZoneId, d.Id}, dot)
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

	var d Device
	d.Id = nxid.New().String()
	d.Agent = info.Agent
	d.IsEnabled = info.IsEnabled
	d.IsTrusted = info.IsTrusted
	d.IP = info.IP.String()
	d.Location = info.Location
	d.UserId = info.UserId
	d.ZoneId = info.ZoneId
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

func (ds *DeviceStore) GetDeviceFromDeviceInfo(ctx context.Context, info DeviceInfo) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(info.FingerprintId) != 0 {
		var deviceFromFingerprint, getDeviceFromFingerprintErr = ds.GetDeviceWithFingerprint(ctx, info.FingerprintId)
		if getDeviceFromFingerprintErr != nil {
			return nil, nerror.WrapOnly(getDeviceFromFingerprintErr)
		}
		return deviceFromFingerprint, nil
	}

	var device, getDeviceErr = ds.GetDeviceWithIPAndCity(ctx, info.IP.String(), info.Location.City, info.FingerprintId)
	if getDeviceErr == nil {
		return device, nil
	}

	return nil, nerror.New("device not found", info)
}

func (ds *DeviceStore) RemoveAllDevicesForZoneId(ctx context.Context, zoneId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(zoneId) == 0 {
		return nerror.New("neither value can be empty").
			Add("zoneId", zoneId)
	}

	var userQuery = query.NewMatchQuery("ZoneId: " + zoneId)
	var req = bleve.NewSearchRequest(userQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nerror.Wrap(searchErr, "searching for ip").
			Add("zoneId", zoneId)
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

// GetDeviceForZoneId returns found device matching zoneId and deviceId.
func (ds *DeviceStore) GetDeviceForZoneId(ctx context.Context, zoneId string, deviceId string) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(deviceId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("deviceId", deviceId).Add("zoneId", zoneId)
	}

	var idQuery = query.NewMatchQuery("Id: " + deviceId)
	var sessionQuery = query.NewMatchQuery("ZoneId: " + zoneId)

	var queryList = []query.Query{sessionQuery, idQuery}
	var searchQuery = query.NewConjunctionQuery(queryList)
	var req = bleve.NewSearchRequest(searchQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for id").
			Add("deviceId", deviceId).Add("zoneId", zoneId)
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
			Add("deviceId", deviceId).Add("zoneId", zoneId)
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

// RemoveDevice returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) RemoveDevice(ctx context.Context, id string) (*Device, error) {
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
	var deviceData, getErr = ds.Store.Remove(matcher.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr).Add("id", id)
	}

	var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr).Add("id", id)
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

// GetAllDevicesForZoneId returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetAllDevicesForZoneId(ctx context.Context, zoneId string) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(zoneId) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("zoneId", zoneId)
	}

	var userQuery = query.NewMatchQuery("ZoneId: " + zoneId)
	var req = bleve.NewSearchRequest(userQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("zoneId", zoneId)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var devices = make([]Device, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = ds.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr).Add("zoneId", zoneId)
		}

		var decodedDevice, decodeErr = ds.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr).Add("zoneId", zoneId)
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

// GetAllDevicesWithCity returns found device matching ip and city, and if provided, fingerprintId.
func (ds *DeviceStore) GetAllDevicesWithCity(ctx context.Context, city string) ([]Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(city) == 0 {
		return nil, nerror.New("neither value can be empty").
			Add("city", city)
	}

	var cityQuery = query.NewMatchQuery("Location.City: " + city)

	var req = bleve.NewSearchRequest(cityQuery)

	var searchResult, searchErr = ds.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for ip").
			Add("city", city)
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

type DeviceService struct {
	Codec  Codec
	Store  *DeviceStore
	Topics sabuhp.TopicPartial
}

func (cs *DeviceService) RegisterWithBus(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(GetDevicesForCityTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetDevicesWithCity))
	bus.Group(GetDevicesForUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetDevicesForUser))
	bus.Group(GetDevicesForCityAndIpTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetDevicesWithCityAndIp))
	bus.Group(GetDevicesForZoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetDevicesForZoneId))
	bus.Group(GetAllDevicesTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetAll))
	bus.Group(GetDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetDevice))
	bus.Group(UpdateDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.UpdateDevice))
	bus.Group(DisableDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.DisableDevice))
	bus.Group(EnableDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.EnableDevice))
	bus.Group(CreateDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateDevice))
	bus.Group(RemoveDeviceTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.DeleteDevice))
	bus.Group(RemoveDevicesForZoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.DeleteDevicesForZoneId))
}

func (cs *DeviceService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
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

func (cs *DeviceService) GetDevicesWithCityAndIp(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var ip = msg.Params.Get("ip")
	var city = msg.Params.Get("city")
	if len(city) == 0 || len(ip) == 0 {
		var getAllErr = nerror.New("city or ip param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetAllDevicesWithIPAndCity(ctx, ip, city)
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

func (cs *DeviceService) GetDevicesForZoneId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var zoneId = msg.Params.Get("zoneId")
	if len(zoneId) == 0 {
		var getAllErr = nerror.New("zoneId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetAllDevicesForZoneId(ctx, zoneId)
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

func (cs *DeviceService) GetDevicesForUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetAllDevicesForUserId(ctx, userId)
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

func (cs *DeviceService) GetDevicesWithCity(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var city = msg.Params.Get("city")
	if len(city) == 0 {
		var getAllErr = nerror.New("city param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetAllDevicesWithCity(ctx, city)
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

func (cs *DeviceService) GetDeviceWithFingerprint(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var fingerprintId = msg.Params.Get("fingerprintId")
	if len(fingerprintId) == 0 {
		var getAllErr = nerror.New("fingerprintId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetDeviceWithFingerprint(ctx, fingerprintId)
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

func (cs *DeviceService) DeleteDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var deviceId = msg.Params.Get("deviceId")
	if len(deviceId) == 0 {
		var getAllErr = nerror.New("deviceId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.RemoveDevice(ctx, deviceId)
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
	newCraftedReply.Params.Set("deviceId", deviceId)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeviceRemovedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *DeviceService) UpdateDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Device
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var createdGroup, updateErr = cs.Store.Update(ctx, &update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, createdGroup); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeviceUpdatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *DeviceService) CreateDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update DeviceInfo
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var createdGroup, updateErr = cs.Store.Create(ctx, update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, createdGroup); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeviceCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *DeviceService) DeleteDevicesForZoneId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var zoneId = msg.Params.Get("zoneId")
	if len(zoneId) == 0 {
		var getAllErr = nerror.New("zoneId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var getAllErr = cs.Store.RemoveAllDevicesForZoneId(ctx, zoneId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Params.Set("zoneId", zoneId)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DevicesRemovedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *DeviceService) GetDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var deviceId = msg.Params.Get("deviceId")
	if len(deviceId) == 0 {
		var getAllErr = nerror.New("deviceId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetDevice(ctx, deviceId)
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

func (cs *DeviceService) DisableDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var deviceId = msg.Params.Get("deviceId")
	if len(deviceId) == 0 {
		var getAllErr = nerror.New("deviceId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetDevice(ctx, deviceId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	record.IsEnabled = false

	var updatedRecord, updateErr = cs.Store.Update(ctx, record)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, updatedRecord); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeviceDisabledTopic)
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *DeviceService) EnableDevice(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var deviceId = msg.Params.Get("deviceId")
	if len(deviceId) == 0 {
		var getAllErr = nerror.New("deviceId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.GetDevice(ctx, deviceId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	record.IsEnabled = true

	var updatedRecord, updateErr = cs.Store.Update(ctx, record)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, updatedRecord); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeviceEnabledTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}
