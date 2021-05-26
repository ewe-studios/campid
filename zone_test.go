package campid

import (
	"context"
	"testing"
	"time"

	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/influx6/npkg/nxid"
	"github.com/stretchr/testify/require"
)

func TestSessionStore(t *testing.T) {
	var store = nmap.NewExprByteStore(100)
	var sessionStore = NewSessionStore(&JsonSessionCodec{}, store)

	var sz Zone
	sz.UserId = "1"
	sz.CsrfMessage = "m"
	sz.Updated = time.Now()
	sz.Created = time.Now()
	sz.Method = "web-client"
	sz.Id = nxid.New().String()

	var sz2 Zone
	sz2.UserId = "1"
	sz2.CsrfMessage = "m"
	sz2.Updated = time.Now()
	sz2.Created = time.Now()
	sz2.Method = "mobile-client"
	sz2.Id = nxid.New().String()

	var ctx = context.Background()

	t.Run("Save", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)
	})
	t.Run("Update", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		sz.Method = "mobile-client"
		require.NoError(t, sessionStore.Update(ctx, &sz))

		var record, retreivedErr = sessionStore.GetById(ctx, sz.Id, sz.UserId)
		require.NoError(t, retreivedErr)
		require.Equal(t, record.UserId, sz.UserId)
		require.Equal(t, "mobile-client", record.Method)
	})
	t.Run("GetAll", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		var recordList, getListErr = sessionStore.GetAll(ctx)
		require.NoError(t, getListErr)
		require.Len(t, recordList, 1)
	})
	t.Run("GetAllForUser", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))
		require.NoError(t, sessionStore.Save(ctx, &sz2))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		var recordList, getListErr = sessionStore.GetAllForUser(ctx, sz.UserId)
		require.NoError(t, getListErr)
		require.Len(t, recordList, 2)
	})
	t.Run("GetOneForUser", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		var record, getListErr = sessionStore.GetOneForUser(ctx, sz.UserId)
		require.NoError(t, getListErr)
		require.NotNil(t, record)
		require.Equal(t, record.UserId, sz.UserId)
	})
	t.Run("remove", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))
		require.NoError(t, sessionStore.Save(ctx, &sz2))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		var hasRecord2, hasRecordErr2 = sessionStore.Has(ctx, sz2.Id, sz2.UserId)
		require.NoError(t, hasRecordErr2)
		require.True(t, hasRecord2)

		var record, getListErr = sessionStore.Remove(ctx, sz.Id, sz.UserId)
		require.NoError(t, getListErr)
		require.NotNil(t, record)
		require.Equal(t, record.Id, sz.Id)

		hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.False(t, hasRecord)

		hasRecord2, hasRecordErr2 = sessionStore.Has(ctx, sz2.Id, sz2.UserId)
		require.NoError(t, hasRecordErr2)
		require.True(t, hasRecord2)
	})
	t.Run("RemoveAllForUser", func(t *testing.T) {
		store.Clear()

		require.NoError(t, sessionStore.Save(ctx, &sz))
		require.NoError(t, sessionStore.Save(ctx, &sz2))

		var hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.True(t, hasRecord)

		var hasRecord2, hasRecordErr2 = sessionStore.Has(ctx, sz2.Id, sz2.UserId)
		require.NoError(t, hasRecordErr2)
		require.True(t, hasRecord2)

		var getListErr = sessionStore.RemoveAllForUser(ctx, sz.UserId)
		require.NoError(t, getListErr)

		hasRecord, hasRecordErr = sessionStore.Has(ctx, sz.Id, sz.UserId)
		require.NoError(t, hasRecordErr)
		require.False(t, hasRecord)

		hasRecord2, hasRecordErr2 = sessionStore.Has(ctx, sz2.Id, sz2.UserId)
		require.NoError(t, hasRecordErr2)
		require.False(t, hasRecord2)
	})
}
