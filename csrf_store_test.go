package campid

import (
	"context"
	"testing"
	"time"

	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/stretchr/testify/require"
)

func TestCSRFStore(t *testing.T) {
	var sessionId = "1"
	var ctx = context.Background()
	var store = nmap.NewExprByteStore(100)
	var csrfStore = NewCSRFStore(store, 1*time.Minute)

	t.Run("GetOrCreate", func(t *testing.T) {
		store.Clear()

		var token, err = csrfStore.GetOrCreate(ctx, sessionId)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		var retreivedToken, err2 = csrfStore.Get(ctx, sessionId)
		require.NoError(t, err2)
		require.NotEmpty(t, retreivedToken)
		require.Equal(t, retreivedToken, token)
	})

	t.Run("GetOrCreateWithDur", func(t *testing.T) {
		store.Clear()

		var token, err = csrfStore.GetOrCreateWithDur(ctx, sessionId, time.Minute * 2)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		var retreivedToken, err2 = csrfStore.Get(ctx, sessionId)
		require.NoError(t, err2)
		require.NotEmpty(t, retreivedToken)
		require.Equal(t, retreivedToken, token)
	})

	t.Run("GetAll", func(t *testing.T) {
		store.Clear()

		var token, err = csrfStore.GetOrCreate(ctx, sessionId)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		var tokenList, err2 = csrfStore.GetAll(ctx)
		require.NoError(t, err2)
		require.NotEmpty(t, tokenList)
	})

	t.Run("Delete", func(t *testing.T) {
		store.Clear()

		var token, err = csrfStore.GetOrCreate(ctx, sessionId)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		var retreivedToken, err2 = csrfStore.Get(ctx, sessionId)
		require.NoError(t, err2)
		require.NotEmpty(t, retreivedToken)
		require.Equal(t, retreivedToken, token)

		var deletedToken, deleteErr = csrfStore.Delete(ctx, sessionId)
		require.NoError(t, deleteErr)
		require.Equal(t, retreivedToken, deletedToken)

		var _, getErr = csrfStore.Get(ctx, sessionId)
		require.Error(t, getErr)
	})
}
