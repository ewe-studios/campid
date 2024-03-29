package campid

import (
	"context"
	"os"
	"testing"

	"github.com/blevesearch/bleve/v2"
	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/influx6/npkg/nxid"
	"github.com/stretchr/testify/require"
)

func TestRbacGroup(t *testing.T) {
	defer os.RemoveAll(t.Name())

	var indexMapping, indexMappingErr = CreateIndexMappingForAll()
	require.NoError(t, indexMappingErr)

	var store = nmap.NewExprByteStore(100)

	var myGroup Group
	myGroup.Name = "wonderbar"
	myGroup.Roles = []Role{
		{
			Id:   nxid.New().String(),
			Name: "alarm",
		},
		{
			Id:   nxid.New().String(),
			Name: "disalarm",
		},
	}

	var ctx = context.Background()

	t.Run("add", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
	})

	t.Run("ById", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)
	})
	t.Run("RemoveById", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.RemoveById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		var hasRecord, checkErr = grpStore.HasGroup(ctx, createdRecord.Name)
		require.NoError(t, checkErr)
		require.False(t, hasRecord)
	})
	t.Run("Update", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		retrievedRecord.Name = "wonderbat-group"
		var updateErr = grpStore.Update(ctx, retrievedRecord)
		require.NoError(t, updateErr)

		var retrievedRecord2, retreiveErr2 = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr2)
		require.Equal(t, retrievedRecord.Id, retrievedRecord2.Id)
		require.Equal(t, retrievedRecord.Name, retrievedRecord2.Name)
		require.NotEqual(t, myGroup.Name, retrievedRecord2.Name)

	})

	t.Run("GroupsWithRoles", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		var records, updateErr = grpStore.GroupsWithRoles(ctx, "alarm", "disalarm")
		require.NoError(t, updateErr)
		require.NotEmpty(t, records)
		require.Len(t, records, 1)
	})

	t.Run("GroupsWithAnyRoles", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		var records, updateErr = grpStore.GroupsWithAnyRoles(ctx, "alarm", "disalarm")
		require.NoError(t, updateErr)
		require.NotEmpty(t, records)
		require.Len(t, records, 1)
	})

	t.Run("GroupsWithRole", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		var records, updateErr = grpStore.GroupsWithRoles(ctx, "alarm")
		require.NoError(t, updateErr)
		require.NotEmpty(t, records)
		require.Len(t, records, 1)
	})
	t.Run("HasGroup", func(t *testing.T) {
		defer os.RemoveAll(t.Name())
		os.RemoveAll(t.Name())
		store.Clear()

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var grpStore = NewGroupStore(store, &JsonGroupCodec{}, indexer)

		var createdRecord, createErr = grpStore.Add(ctx, myGroup)
		require.NoError(t, createErr)
		require.NotNil(t, createdRecord)
		require.NotEmpty(t, createdRecord.Id)

		var retrievedRecord, retreiveErr = grpStore.ById(ctx, createdRecord.Id)
		require.NoError(t, retreiveErr)
		require.Equal(t, createdRecord.Id, retrievedRecord.Id)

		var hasRecord, updateErr = grpStore.HasGroup(ctx, createdRecord.Name)
		require.NoError(t, updateErr)
		require.True(t, hasRecord)
	})
}
