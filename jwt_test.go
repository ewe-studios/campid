package campid

import (
	"context"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/stretchr/testify/require"
)

var myKey = []byte("secret234532wergeg*")
var myUser = "1"
var mySessionId = "ses_1"

func TestJwtManufacturer(t *testing.T) {
	var config JWTConfig
	config.GetTime = time.Now
	config.MapCodec = &JsonMapCodec{}
	config.GetNewClaim = func() (jwt.MapClaims, jwt.SigningMethod, interface{}) {
		return jwt.MapClaims{
			"keym": "V1",
		}, jwt.SigningMethodHS256, myKey
	}

	config.GetSigningKey = func(t *jwt.Token) (key interface{}, err error) {
		if _, isHMAC := t.Method.(*jwt.SigningMethodHMAC); !isHMAC {
			return nil, nerror.New("invalid signing method %q", t.Method.Alg())
		}
		return myKey, nil
	}

	config.Issuer = "Test"
	config.Authorizer = "TestAPI"
	config.AccessTokenExpiration = 1 * time.Minute
	config.RefreshTokenExpiration = 3 * time.Minute

	var store = nmap.NewExprByteStore()
	config.Store = store

	var manager = NewJWTStore(config)

	var ctx = context.Background()

	t.Run("Create", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.NotEmpty(t, claim.RandomId)
		require.Len(t, claim.RandomId, 30)
		require.NotEmpty(t, claim.UserId)
		require.True(t, claim.IsUsable)
		require.Equal(t, myUser, claim.UserId)
	})

	t.Run("CreateWithData", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, map[string]string{"day": "2"})
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.NotEmpty(t, claim.RandomId)
		require.Len(t, claim.RandomId, 30)
		require.NotEmpty(t, claim.UserId)
		require.True(t, claim.IsUsable)
		require.Equal(t, myUser, claim.UserId)
		require.NotNil(t, claim.Data)
		require.Equal(t, "2", claim.Data["day"])
	})

	t.Run("CreateWithDataAndVerifyAccess", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, map[string]string{"day": "2"})
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.NotEmpty(t, claim.RandomId)
		require.Len(t, claim.RandomId, 30)
		require.NotEmpty(t, claim.UserId)
		require.True(t, claim.IsUsable)
		require.Equal(t, myUser, claim.UserId)
		require.NotNil(t, claim.Data)
		require.Equal(t, "2", claim.Data["day"])

		var verifiedClaim, _, verifiedErr = manager.VerifyAccess(ctx, claim.AccessToken)
		require.NoError(t, verifiedErr)
		require.Equal(t, claim.RefreshId, verifiedClaim.RefreshId)
		require.NotNil(t, verifiedClaim.Data)
		require.Equal(t, "2", verifiedClaim.Data["day"])
	})

	t.Run("VerifyAccess", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var verifiedClaim, _, verifiedErr = manager.VerifyAccess(ctx, claim.AccessToken)
		require.NoError(t, verifiedErr)
		require.Equal(t, claim.RefreshId, verifiedClaim.RefreshId)
	})

	t.Run("Refresh", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)

		require.Equal(t, myUser, claim.UserId)

		var refreshedClaim, refreshedClaimErr = manager.Refresh(ctx, claim.RefreshToken)
		require.NoError(t, refreshedClaimErr)

		require.NotEqual(t, refreshedClaim.RandomId, claim.RandomId)
		require.NotEqual(t, refreshedClaim.RefreshToken, claim.RefreshToken)
		require.NotEqual(t, refreshedClaim.AccessToken, claim.AccessToken)
		require.NotEqual(t, refreshedClaim.AccessId, claim.AccessId)
		require.Equal(t, refreshedClaim.UserId, claim.UserId)

		require.Equal(t, refreshedClaim.Id.String(), claim.Id.String())
		require.False(t, refreshedClaim.ParentAccessId.IsNil())
		require.Equal(t, refreshedClaim.ParentAccessId.String(), claim.AccessId.String())

		// validate that accessId is still in the store.
		var accessUserId, accessUserIdGetErr = manager.GetUserIdByAccessId(ctx, refreshedClaim.ParentAccessId.String())
		require.NoError(t, accessUserIdGetErr)
		require.Equal(t, claim.UserId, accessUserId)

		// verify new claim, every thing should be fine but next time we use
		// parent accessId, it should fail because it's being removed.
		var verifiedClaim, _, verifiedErr = manager.VerifyAccess(ctx, refreshedClaim.AccessToken)
		require.NoError(t, verifiedErr)
		require.Equal(t, refreshedClaim.RefreshId, verifiedClaim.RefreshId)

		// this should fail
		_, accessUserIdGetErr = manager.GetUserIdByAccessId(ctx, refreshedClaim.ParentAccessId.String())
		require.Error(t, accessUserIdGetErr)
	})

	t.Run("GetRefreshTokenByRefreshId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var refreshToken, getErr = manager.GetRefreshTokenById(ctx, claim.RefreshId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.RefreshToken, refreshToken)
	})

	t.Run("GetAll", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var idList, getErr = manager.GetAllJwtIds(ctx)
		require.NoError(t, getErr)
		require.Len(t, idList, 1)
	})

	t.Run("GetUserIdByAccessId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var userId, getErr = manager.GetUserIdByAccessId(ctx, claim.AccessId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.UserId, userId)
	})

	t.Run("RemoveRefreshId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.Equal(t, myUser, claim.UserId)

		var token, getErr = manager.RemoveRefreshId(ctx, claim.RefreshId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.RefreshToken, token)

		var _, getErr2 = manager.GetRefreshTokenById(ctx, claim.RefreshId.String())
		require.Error(t, getErr2)
	})

	t.Run("RemoveAccessId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.Equal(t, myUser, claim.UserId)

		var userId, getErr = manager.RemoveAccessId(ctx, claim.AccessId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.UserId, userId)

		var _, getErr2 = manager.GetUserIdByAccessId(ctx, claim.AccessId.String())
		require.Error(t, getErr2)
	})

	t.Run("RemoveJwtId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var getErr = manager.RemoveJwtId(ctx, claim.Id.String())
		require.NoError(t, getErr)
	})

	t.Run("RemoveWithJwtIdAndSessionId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var getErr = manager.RemoveWithJwtIdAndSessionId(ctx, claim.Id.String(), mySessionId)
		require.NoError(t, getErr)
	})

	t.Run("GetJwtAcccessAndRequestId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var accessId, refreshId, getErr = manager.GetAccessIdAndRefreshIdByJwtId(ctx, claim.Id.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.RefreshId.String(), refreshId)
		require.Equal(t, claim.AccessId.String(), accessId)
	})

	t.Run("GetAllAccessIds", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var ids, getErr = manager.GetAllAccessIds(ctx)
		require.NoError(t, getErr)
		require.Len(t, ids, 1)
		require.Equal(t, claim.AccessId.String(), ids[0])
	})

	t.Run("GetAllRefreshIds", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, mySessionId, myUser, nil)
		require.NoError(t, err)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.RefreshId)
		require.NotEmpty(t, claim.AccessId)
		require.Equal(t, myUser, claim.UserId)

		var ids, getErr = manager.GetAllRefreshIds(ctx)
		require.NoError(t, getErr)
		require.Len(t, ids, 1)
		require.Equal(t, claim.RefreshId.String(), ids[0])
	})
}
