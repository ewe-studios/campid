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

func TestJwtManufacturer(t *testing.T) {
	var config JWTConfig
	config.GetTime = time.Now
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

	var manager = NewJWTManufacturer(config)

	t.Run("Create", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(context.Background(), myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.NotEmpty(t, claim.AccessId)
		require.NotEmpty(t, claim.RandomId)
		require.Len(t, claim.RandomId, 30)
		require.NotEmpty(t, claim.UserId)
		require.True(t, claim.IsUsable)
		require.Equal(t, myUser, claim.UserId)
	})

	var ctx = context.Background()

	t.Run("VerifyAccess", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var verifiedClaim, _, verifiedErr = manager.VerifyAccess(ctx, claim.AccessToken)
		require.NoError(t, verifiedErr)
		require.Equal(t, claim.Id, verifiedClaim.Id)
	})

	t.Run("Refresh", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var refreshedClaim, refreshedClaimErr = manager.Refresh(ctx, claim.RefreshToken)
		require.NoError(t, refreshedClaimErr)

		require.NotEqual(t, refreshedClaim.RandomId, claim.RandomId)
		require.NotEqual(t, refreshedClaim.RefreshToken, claim.RefreshToken)
		require.NotEqual(t, refreshedClaim.AccessToken, claim.AccessToken)
		require.NotEqual(t, refreshedClaim.AccessId, claim.AccessId)
		require.Equal(t, refreshedClaim.UserId, claim.UserId)
	})

	t.Run("GetRefreshTokenByRefreshId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var refreshToken, getErr = manager.GetRefreshTokenById(ctx, claim.Id.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.RefreshToken, refreshToken)
	})

	t.Run("GetUserIdByAccessId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var userId, getErr = manager.GetUserIdByAccessId(ctx, claim.AccessId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.UserId, userId)
	})

	t.Run("RemoveRefreshId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var token, getErr = manager.RemoveRefreshId(ctx, claim.Id.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.RefreshToken, token)

		var _, getErr2 = manager.GetRefreshTokenById(ctx, claim.Id.String())
		require.Error(t, getErr2)
	})

	t.Run("RemoveAccessId", func(t *testing.T) {
		store.Clear()

		var claim, err = manager.Create(ctx, myUser)
		require.NoError(t, err)
		require.NotEmpty(t, claim.AccessToken)
		require.NotEmpty(t, claim.RefreshToken)
		require.NotEmpty(t, claim.Id)
		require.Equal(t, myUser, claim.UserId)

		var userId, getErr = manager.RemoveAccessId(ctx, claim.AccessId.String())
		require.NoError(t, getErr)
		require.Equal(t, claim.UserId, userId)

		var _, getErr2 = manager.GetUserIdByAccessId(ctx, claim.AccessId.String())
		require.Error(t, getErr2)
	})
}
