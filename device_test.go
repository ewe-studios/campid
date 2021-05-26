package campid

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/blevesearch/bleve/v2"
	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/stretchr/testify/require"
	"xojoc.pw/useragent"
)

func TestDeviceStore(t *testing.T) {
	defer os.RemoveAll(t.Name())
	os.RemoveAll(t.Name())

	var indexMapping, indexMappingErr = CreateIndexMappingForAll()
	require.NoError(t, indexMappingErr)

	var store = nmap.NewExprByteStore(100)

	var myDevice DeviceInfo
	myDevice.FingerprintId = "10"
	myDevice.UserId = "1110"
	myDevice.SessionId = "23"
	myDevice.IP = net.IPv4('4', '1', '1', '1')
	myDevice.Agent = &Agent{
		Browser: "Firefox",
		UserAgent: &useragent.UserAgent{
			Original: "Firefox",
			Mobile:   true,
		},
	}
	myDevice.Location.City = "lagos"
	myDevice.Location.State = "Lagos"
	myDevice.Location.Country = "Nigeria"
	myDevice.Location.Postal = "P.O.Box 6236"
	myDevice.Location.Street = "Wella Fela Goro"

	var ctx = context.Background()

	t.Run("CreateZone", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)
	})
	t.Run("Update", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)

		retrievedRecord.Location.State = "Ogun"
		var updatedRecord, updateErr = deviceStore.Update(ctx, retrievedRecord)
		require.NoError(t, updateErr)
		require.NotNil(t, updatedRecord)
		require.Equal(t, createdRecord.Id, updatedRecord.Id)
		require.Equal(t, myDevice.SessionId, updatedRecord.SessionId)
		require.Equal(t, retrievedRecord.Location.State, updatedRecord.Location.State)

		var retrievedRecord2, retreiveErr2 = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr2)
		require.Equal(t, createdRecord.Id, retrievedRecord2.Id)
		require.Equal(t, myDevice.SessionId, retrievedRecord2.SessionId)
		require.Equal(t, retrievedRecord.Location.State, retrievedRecord2.Location.State)
	})
	t.Run("GetAll", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var records, retreiveErr = deviceStore.GetAll(ctx)
		require.NoError(t, retreiveErr)
		require.NotEmpty(t, records)
	})
	t.Run("remove", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retreiveErr = deviceStore.Remove(ctx, createdRecord)
		require.NoError(t, retreiveErr)

		var _, retreiveErr2 = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.Error(t, retreiveErr2)
	})
	t.Run("GetDevice", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)
	})
	t.Run("GetDeviceForSessionId", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDeviceForSessionId(ctx, createdRecord.SessionId, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)
	})
	t.Run("HasIP", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var hasRecord, retreiveErr = deviceStore.HasIP(ctx, createdRecord.IP)
		require.NoError(t, retreiveErr)
		require.True(t, hasRecord)
	})
	t.Run("HasStreet", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var hasRecord, retreiveErr = deviceStore.HasStreet(ctx, createdRecord.Location.Street)
		require.NoError(t, retreiveErr)
		require.True(t, hasRecord)
	})
	t.Run("HasDevicesWithIPAndCity", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var hasRecord, retreiveErr = deviceStore.HasDeviceWithIPAndCity(ctx, createdRecord.IP, createdRecord.Location.City)
		require.NoError(t, retreiveErr)
		require.True(t, hasRecord)
	})
	t.Run("GetDeviceWithIPAndCityWithFingerprint", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDeviceWithIPAndCity(ctx, createdRecord.IP, createdRecord.Location.City, createdRecord.FingerprintId)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)
	})
	t.Run("GetDeviceWithIPAndCity", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDeviceWithIPAndCity(ctx, createdRecord.IP, createdRecord.Location.City, "")
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)
	})
	t.Run("GetAllDevicesForUserId", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var records, retreiveErr = deviceStore.GetAllDevicesForUserId(ctx, createdRecord.UserId)
		require.NoError(t, retreiveErr)
		require.NotEmpty(t, records)
	})
	t.Run("GetAllDevicesWithIPAndCity", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var records, retreiveErr = deviceStore.GetAllDevicesWithIPAndCity(ctx, createdRecord.IP, createdRecord.Location.City)
		require.NoError(t, retreiveErr)
		require.NotEmpty(t, records)
	})
	t.Run("GetAllDevicesForSessionId", func(t *testing.T) {
		os.RemoveAll(t.Name())
		defer os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var records, retreiveErr = deviceStore.GetAllDevicesForSessionId(ctx, createdRecord.SessionId)
		require.NoError(t, retreiveErr)
		require.NotEmpty(t, records)
	})
	t.Run("RemoveAllDevicesForSessionId", func(t *testing.T) {
		os.RemoveAll(t.Name())
		defer os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, store, indexer)

		var createdRecord, createErr = deviceStore.Create(ctx, myDevice)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = deviceStore.GetDevice(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
		require.Equal(t, myDevice.SessionId, createdRecord.SessionId)

		var removeErr = deviceStore.RemoveAllDevicesForSessionId(ctx, createdRecord.SessionId)
		require.NoError(t, removeErr)

		var records, retreiveErr2 = deviceStore.GetAllDevicesForSessionId(ctx, createdRecord.SessionId)
		require.Error(t, retreiveErr2)
		require.Empty(t, records)
	})
}
