package campid

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage/nmap"
	"github.com/stretchr/testify/require"
	"xojoc.pw/useragent"
)

func TestSessionManager(t *testing.T) {
	defer os.RemoveAll(t.Name())

	os.RemoveAll(t.Name())

	var myUserId = "1110"
	var myMethod = "web-client"
	var myjwtData = map[string]string{}
	var mySessionData = map[string]string{}

	var sessionStorage = nmap.NewExprByteStore(100)
	var jwtStorage = nmap.NewExprByteStore(100)
	var deviceStorage = nmap.NewExprByteStore(100)

	var clearAllStorage = func() {
		jwtStorage.Clear()
		deviceStorage.Clear()
		sessionStorage.Clear()
	}

	var myDevice DeviceInfo
	myDevice.FingerprintId = "11"
	myDevice.UserId = myUserId
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

	var myDevice2 DeviceInfo
	myDevice2.FingerprintId = "10"
	myDevice2.UserId = myUserId
	myDevice2.IP = net.IPv4('4', '1', '1', '1')
	myDevice2.Agent = &Agent{
		Browser: "Firefox",
		UserAgent: &useragent.UserAgent{
			Original: "Firefox",
			Mobile:   true,
		},
	}
	myDevice2.Location.City = "lagos"
	myDevice2.Location.State = "Lagos"
	myDevice2.Location.Country = "Nigeria"
	myDevice2.Location.Postal = "P.O.Box 6236"
	myDevice2.Location.Street = "Wella Fela Goro"

	var config JWTConfig
	config.Issuer = "Test"
	config.Authorizer = "TestAPI"
	config.Store = jwtStorage
	config.GetTime = time.Now
	config.MapCodec = &JsonMapCodec{}
	config.AccessTokenExpiration = 1 * time.Minute
	config.RefreshTokenExpiration = 3 * time.Minute
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

	var indexMapping, indexMappingErr = CreateIndexMappingForAll()
	require.NoError(t, indexMappingErr)

	var indexer, indexerErr = bleve.New(t.Name(), indexMapping)
	require.NoError(t, indexerErr)
	require.NotNil(t, indexer)

	defer indexer.Close()

	var jwtStore = NewJWTStore(config)
	var sessionStore = NewZoneStore(&JsonZoneCodec{Codec: JsonCodec{}}, sessionStorage)
	var deviceStore = NewDeviceStore(&JsonDeviceCodec{}, deviceStorage, indexer)

	var ctx = context.Background()
	var sessionManager = NewZoneManager(sessionStore, jwtStore, deviceStore)

	defer clearAllStorage()

	var sz, cm, dr, createErr = sessionManager.CreateZoneWithJwtAndDevice(ctx, myUserId, myMethod, myDevice, myjwtData, mySessionData)
	require.NoError(t, createErr)
	require.NotNil(t, sz)
	require.NotNil(t, cm)
	require.NotNil(t, dr)

	require.NotEmpty(t, sz.Id)
	require.NotEmpty(t, cm.ZoneId)

	require.Equal(t, sz.Id, cm.ZoneId)
	require.Equal(t, sz.Id, dr.ZoneId)

	var sz2, clm2, err = sessionManager.Refresh(ctx, sz.Id, sz.UserId, cm.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, clm2)
	require.NotNil(t, sz2)
	require.NotEqual(t, cm.AccessId, clm2.AccessId)
	require.NotEqual(t, cm.AccessToken, clm2.AccessToken)
	require.NotEqual(t, cm.RefreshToken, clm2.RefreshToken)
	require.NotEqual(t, cm.RefreshId, clm2.RefreshId)
	require.Equal(t, sz.Id, sz2.Id)

	var sz3, clm3, token, err2 = sessionManager.Verify(ctx, sz.Id, sz.UserId, cm.AccessToken)
	require.NoError(t, err2)
	require.NotNil(t, token)
	require.NotNil(t, clm3)
	require.NotNil(t, sz3)
	require.Equal(t, sz.Id, sz3.Id)

	var sz4, err3 = sessionManager.Get(ctx, sz3.UserId)
	require.NoError(t, err3)
	require.NotNil(t, sz4)
	require.Equal(t, sz.Id, sz4.Id)

	var sz6, devices, getSzAndDvErr = sessionManager.GetSessionAndDevices(ctx, sz.Id, sz.UserId)
	require.NoError(t, getSzAndDvErr)
	require.NotNil(t, sz6)
	require.Len(t, devices, 1)
	require.Equal(t, devices[0].Id, dr.Id)

	var sz7, claimList, getClaimsListErr = sessionManager.GetSessionAndJwtClaims(ctx, sz.Id, sz.UserId)
	require.NoError(t, getClaimsListErr)
	require.NotNil(t, claimList)
	require.NotNil(t, sz7)
	require.Len(t, claimList, 1)

	var trustedDevice, trustDeviceErr = sessionManager.TrustDevice(ctx, sz.Id, dr.Id)
	require.NoError(t, trustDeviceErr)
	require.NotNil(t, trustedDevice)
	require.True(t, trustedDevice.IsTrusted)

	var deviceFromStore, getDvErr = deviceStore.GetDevice(ctx, dr.Id)
	require.NoError(t, getDvErr)
	require.NotNil(t, deviceFromStore)
	require.True(t, deviceFromStore.IsTrusted)

	var distrustedDevice, distrustDeviceErr = sessionManager.DistrustDevice(ctx, sz.Id, dr.Id)
	require.NoError(t, distrustDeviceErr)
	require.NotNil(t, distrustedDevice)
	require.False(t, distrustedDevice.IsTrusted)

	deviceFromStore, getDvErr = deviceStore.GetDevice(ctx, dr.Id)
	require.NoError(t, getDvErr)
	require.NotNil(t, deviceFromStore)
	require.False(t, deviceFromStore.IsTrusted)

	var _, doOpErr = sessionManager.EnableDevice(ctx, sz.Id, dr.Id)
	require.NoError(t, doOpErr)

	deviceFromStore, getDvErr = deviceStore.GetDevice(ctx, dr.Id)
	require.NoError(t, getDvErr)
	require.NotNil(t, deviceFromStore)
	require.True(t, deviceFromStore.IsEnabled)

	_, doOpErr = sessionManager.DisableDevice(ctx, sz.Id, dr.Id)
	require.NoError(t, doOpErr)

	deviceFromStore, getDvErr = deviceStore.GetDevice(ctx, dr.Id)
	require.NoError(t, getDvErr)
	require.NotNil(t, deviceFromStore)
	require.False(t, deviceFromStore.IsEnabled)

	var sameSession, newClaim, sameDevice, createNewErr = sessionManager.CreateZoneWithJwtAndDevice(ctx, myUserId, myMethod, myDevice, myjwtData, mySessionData)
	require.NoError(t, createNewErr)
	require.NotNil(t, sameSession)
	require.NotNil(t, newClaim)
	require.NotNil(t, sameDevice)

	require.Equal(t, sz.Id, sameSession.Id)
	require.Equal(t, sz.UserId, sameSession.UserId)

	require.Equal(t, dr.Id, sameDevice.Id)
	require.NotEqual(t, newClaim.Id, clm3.Id)

	var _, deviceList, getSzAndDvErr2 = sessionManager.GetSessionAndDevices(ctx, sz.Id, sz.UserId)
	require.NoError(t, getSzAndDvErr2)
	require.Len(t, deviceList, 1)

	var sameSession2, newClaim2, newDevice, createNewErr2 = sessionManager.CreateZoneWithJwtAndDevice(ctx, myUserId, myMethod, myDevice2, myjwtData, mySessionData)
	require.NoError(t, createNewErr2)
	require.NotNil(t, sameSession2)
	require.NotNil(t, newClaim2)
	require.NotNil(t, newDevice)

	require.Equal(t, sz.UserId, sameSession.UserId)
	require.Equal(t, sz.Id, sameSession2.Id)

	require.NotEqual(t, dr.Id, newDevice.Id)
	require.NotEqual(t, newClaim2.Id, clm3.Id)

	var _, deviceList3, getSzAndDvErr3 = sessionManager.GetSessionAndDevices(ctx, sz.Id, sz.UserId)
	require.NoError(t, getSzAndDvErr3)
	require.Len(t, deviceList3, 2)

	var sz5, err4 = sessionManager.DeleteAllForUser(ctx, sz3.Id, sz3.UserId)
	require.NoError(t, err4)
	require.NotNil(t, sz5)
	require.Equal(t, sz.Id, sz5.Id)
}
