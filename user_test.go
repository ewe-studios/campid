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

// var dateValue = time.Date(2020, 11,11,12,0,0,0,time.Local)

var sampleUser = User{
	Pid:            "",
	Id:             nxid.New().String(),
	FirstName:      "Bob",
	LastName:       "John",
	MiddleName:     "A",
	Email:          "bob@boba.com",
	Phone:          "+852-56677987",
	HashedPassword: "345353536666464",
	EmailVerified:  false,
	PhoneVerified:  false,
}

func TestUserStore(t *testing.T) {

	var indexMapping, indexErr = CreateUserIndexMapping()
	require.NoError(t, indexErr)
	require.NotNil(t, indexMapping)

	var userCodec JsonUserCodec
	var store = nmap.NewExprByteStore(100)

	t.Run("Add", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("Update", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		addedUser.MiddleName = "W"

		var updateErr = userStore.Update(context.Background(), addedUser)
		require.NoError(t, updateErr)

		var retrievedUser, retrieveErr = userStore.ByPid(context.Background(), addedUser.Pid)
		require.NoError(t, retrieveErr)
		require.NotNil(t, retrievedUser)
		require.Equal(t, "W", retrievedUser.MiddleName)
		require.NotEqual(t, retrievedUser.MiddleName, sampleUser.MiddleName)
		require.Equal(t, addedUser.Pid, retrievedUser.Pid)
		require.Equal(t, addedUser.Id, retrievedUser.Id)
		require.Equal(t, addedUser.Email, retrievedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("ByPid", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.ByPid(context.Background(), addedUser.Pid)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.NotEmpty(t, returnedUser.Pid)
		require.Equal(t, sampleUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("ById", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.ById(context.Background(), sampleUser.Id)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.NotEmpty(t, returnedUser.Pid)
		require.Equal(t, sampleUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("ByEmail", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.ByEmail(context.Background(), sampleUser.Email)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.NotEmpty(t, returnedUser.Pid)
		require.Equal(t, sampleUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("ByPhone", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.ByPhone(context.Background(), sampleUser.Phone)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.NotEmpty(t, returnedUser.Pid)
		require.Equal(t, sampleUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("HasEmail", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var hasUser, returnErr = userStore.HasEmail(context.Background(), sampleUser.Email)
		require.NoError(t, returnErr)
		require.True(t, hasUser)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("HasPhone", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var hasUser, returnErr = userStore.HasPhone(context.Background(), sampleUser.Phone)
		require.NoError(t, returnErr)
		require.True(t, hasUser)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("RemoveById", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.RemoveById(context.Background(), addedUser.Id)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.Equal(t, addedUser.Pid, returnedUser.Pid)
		require.Equal(t, addedUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})

	t.Run("RemoveByPid", func(t *testing.T) {
		os.RemoveAll(t.Name())

		var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
		require.NoError(t, indexerErr)
		require.NotNil(t, indexer)

		defer indexer.Close()

		var userStore = NewUserStore(
			store,
			&userCodec,
			indexer,
		)

		var addedUser, addErr = userStore.Add(context.Background(), sampleUser)
		require.NoError(t, addErr)
		require.NotNil(t, addedUser)
		require.NotEmpty(t, addedUser.Pid)
		require.Equal(t, sampleUser.Email, addedUser.Email)

		var returnedUser, returnErr = userStore.RemoveByPid(context.Background(), addedUser.Pid)
		require.NoError(t, returnErr)
		require.NotNil(t, returnedUser)
		require.Equal(t, addedUser.Pid, returnedUser.Pid)
		require.Equal(t, addedUser.Email, returnedUser.Email)

		var keys, _ = store.Keys()
		require.NoError(t, store.RemoveKeys(keys...))
	})
}
