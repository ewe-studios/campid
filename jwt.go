package campid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/njson"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
)

const (
	dot               = "."
	jwtIdKey          = "jid"
	refreshIdKey      = "rid"
	accessIdKey       = "acid"
	sessionIdKey      = "_session_id"
	csrfHeader        = "_csrf"
	dataKey           = "_data"
	parentAccessIdKey = "pa_acid"
)

type TimeFunc func() time.Time

func DefaultTimeFunc() time.Time {
	return time.Now()
}

// GetSigningMethodAndKeyForClaim returns a new claim modified accordingly to identify which
// signing method and key were used to sign and create this jwt. This then allows us
// to implement rotating keys.
type GetSigningMethodAndKeyForClaim func() (modClaims jwt.MapClaims, method jwt.SigningMethod, key interface{})

// GetSigningKeyForToken returns the key for giving token if it's a validly signed token.
type GetSigningKeyForToken func(t *jwt.Token) (key interface{}, err error)

type JWTConfig struct {
	Issuer                 string
	Authorizer             string
	GetNewClaim            GetSigningMethodAndKeyForClaim
	GetSigningKey          GetSigningKeyForToken
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	GetTime                TimeFunc
	MapCodec               MapCodec
	Store                  nstorage.ExpirableStore
}

type JWTStore struct {
	JWTConfig
	Logger njson.Logger
}

func NewJWTStore(config JWTConfig) *JWTStore {
	return &JWTStore{
		JWTConfig: config,
	}
}

type DataClaim struct {
	Id             nxid.ID
	RefreshId      nxid.ID
	AccessId       nxid.ID
	ParentAccessId nxid.ID
	SessionId      string
	UserId         string
	RandomId       string
	IsUsable       bool // indicates if userId and RandomId are supplied and valid for use.
}

func (d *DataClaim) Decode(encodedDataClaim string) error {
	var decoded, err = base64.RawStdEncoding.DecodeString(encodedDataClaim)
	if err != nil {
		return nerror.WrapOnly(err)
	}
	var decodedParts = bytes.Split(decoded, nunsafe.String2Bytes(dot))
	if len(decodedParts) != 7 {
		return nerror.New("invalid encoded data token")
	}

	var idErr error
	d.Id, idErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[0]))
	if idErr != nil {
		return nerror.WrapOnly(idErr)
	}

	var ridErr error
	d.RefreshId, ridErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[2]))
	if ridErr != nil {
		return nerror.WrapOnly(ridErr)
	}

	var accessIdErr error
	d.AccessId, accessIdErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[3]))
	if accessIdErr != nil {
		return nerror.WrapOnly(accessIdErr)
	}

	var parentAccessIdErr error
	d.ParentAccessId, parentAccessIdErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[4]))
	if parentAccessIdErr != nil {
		return nerror.WrapOnly(parentAccessIdErr)
	}

	d.UserId = nunsafe.Bytes2String(decodedParts[1])
	d.RandomId = nunsafe.Bytes2String(decodedParts[5])
	d.SessionId = nunsafe.Bytes2String(decodedParts[6])
	d.IsUsable = true
	return nil
}

func (d DataClaim) Encode() string {
	var token = strings.Join([]string{d.Id.String(), d.UserId, d.RefreshId.String(), d.AccessId.String(), d.ParentAccessId.String(), d.RandomId, d.SessionId}, dot)
	return base64.RawStdEncoding.EncodeToString(nunsafe.String2Bytes(token))
}

type Claim struct {
	DataClaim
	AccessToken    string
	RefreshToken   string
	RefreshExpires int64
	AccessExpires  int64
	Data           map[string]string
}

func (jm *JWTStore) Create(ctx context.Context, sessionId string, userId string, data map[string]string) (Claim, error) {
	return jm.CreateWithId(ctx, nxid.New(), sessionId, userId, nxid.NilID(), data)
}

func (jm *JWTStore) CreateWithId(ctx context.Context, jwtId nxid.ID, sessionId string, userId string, parentAccessId nxid.ID, data map[string]string) (Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var c Claim
	c.Data = data
	c.DataClaim.Id = jwtId
	c.DataClaim.UserId = userId
	c.DataClaim.SessionId = sessionId
	c.DataClaim.RefreshId = nxid.New()
	c.DataClaim.AccessId = nxid.New()
	c.DataClaim.ParentAccessId = parentAccessId

	var generatedRefreshBytes, generatedRefreshBytesErr = Bytes(15)
	if generatedRefreshBytesErr != nil {
		return c, nerror.WrapOnly(generatedRefreshBytesErr)
	}

	c.DataClaim.RandomId = hex.EncodeToString(generatedRefreshBytes)
	c.DataClaim.IsUsable = true

	c.RefreshToken = c.DataClaim.Encode()

	var accessExpiration = jm.GetTime().Add(jm.AccessTokenExpiration)
	c.AccessExpires = accessExpiration.Unix()

	var refreshExpiration = jm.GetTime().Add(jm.RefreshTokenExpiration)
	c.RefreshExpires = refreshExpiration.Unix()

	// create claim for access token.
	var reMappedAccessClaim, signingMethodForAccess, signingKeyForAccess = jm.GetNewClaim()

	var encodedMapData = bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(encodedMapData)

	encodedMapData.Reset()

	var encodedData string
	if data != nil {
		var encodedMapErr = jm.MapCodec.Encode(encodedMapData, data)
		if encodedMapErr != nil {
			return c, nerror.WrapOnly(encodedMapErr)
		}

		encodedData = base64.RawStdEncoding.EncodeToString(encodedMapData.Bytes())
	}

	reMappedAccessClaim[dataKey] = encodedData
	reMappedAccessClaim[accessIdKey] = c.AccessId.String()
	reMappedAccessClaim[refreshIdKey] = c.RefreshId.String()
	reMappedAccessClaim[parentAccessIdKey] = parentAccessId
	reMappedAccessClaim[jwtIdKey] = c.Id.String()
	reMappedAccessClaim[sessionIdKey] = sessionId
	reMappedAccessClaim["exp"] = accessExpiration.Unix()
	reMappedAccessClaim["iss"] = jm.Issuer
	reMappedAccessClaim["aud"] = userId

	var jwtAccessToken = jwt.NewWithClaims(signingMethodForAccess, reMappedAccessClaim)
	var accessToken, accessTokenErr = jwtAccessToken.SignedString(signingKeyForAccess)
	if accessTokenErr != nil {
		return c, nerror.WrapOnly(accessTokenErr)
	}

	c.AccessToken = accessToken

	// point the accessId id to the Id.
	var formattedAccessId = jm.formatAccessId(c.AccessId.String())
	if saveErr := jm.Store.SaveTTL(
		formattedAccessId,
		nunsafe.String2Bytes(userId),
		jm.AccessTokenExpiration,
	); saveErr != nil {
		return c, nerror.WrapOnly(saveErr)
	}

	// point the id to the refresh token.
	var formattedRefreshId = jm.formatRefreshId(c.RefreshId.String())
	if saveErr := jm.Store.SaveTTL(
		formattedRefreshId,
		nunsafe.String2Bytes(c.RefreshToken),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		_ = jm.Store.RemoveKeys(formattedAccessId)
		return c, nerror.WrapOnly(saveErr)
	}

	var formattedJwtDataId = jm.formatJwtData(c.Id.String())
	if saveErr := jm.Store.SaveTTL(
		formattedJwtDataId,
		nunsafe.String2Bytes(encodedData),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		_ = jm.Store.RemoveKeys(formattedAccessId, formattedRefreshId)
		return c, nerror.WrapOnly(saveErr)
	}

	var formattedRefreshAndAccessId = jm.formatAccessIdAndRefreshId(c.AccessId.String(), c.RefreshId.String())
	var formattedJwtId = jm.formatJwtId(c.Id.String())
	if saveErr := jm.Store.SaveTTL(
		formattedJwtId,
		nunsafe.String2Bytes(formattedRefreshAndAccessId),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		_ = jm.Store.RemoveKeys(formattedAccessId, formattedRefreshId, formattedJwtDataId)
		return c, nerror.WrapOnly(saveErr)
	}

	var formattedSessionJwtId = jm.formatSessionJwtId(c.Id.String(), sessionId)
	if saveErr := jm.Store.SaveTTL(
		formattedSessionJwtId,
		nunsafe.String2Bytes(formattedRefreshAndAccessId),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		_ = jm.Store.RemoveKeys(formattedAccessId, formattedRefreshId, formattedJwtDataId, formattedJwtId)
		return c, nerror.WrapOnly(saveErr)
	}

	return c, nil
}

// VerifyAccess verifies provided accessToken returning claim extracted from the valid jwt signed
// token.
func (jm *JWTStore) VerifyAccess(ctx context.Context, accessToken string) (Claim, *jwt.Token, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var logs = njson.Log(jm.Logger)

	var c Claim

	var token, mappedClaims, tokenErr = jm.GetToken(ctx, accessToken)
	if tokenErr != nil {
		return c, nil, nerror.WrapOnly(tokenErr)
	}

	// once parentAccessId is valid and we receive verification for new access id,
	// then delete this.
	var parentAccessId, hasParentAccessId = mappedClaims[parentAccessIdKey].(string)
	if hasParentAccessId {
		var parentAccessXid, accessXidErr = nxid.FromString(parentAccessId)
		if accessXidErr != nil {
			return c, nil, nerror.WrapOnly(accessXidErr)
		}

		c.ParentAccessId = parentAccessXid

		// delete parent acess id.
		if !parentAccessXid.IsNil() {
			if _, removeErr := jm.RemoveAccessId(ctx, parentAccessXid.String()); removeErr != nil {
				logs.New().LError().Message("failed to remove parent access id").Error("error", removeErr)
			} else {
				c.ParentAccessId = nxid.NilID()
			}
		}
	}

	if encodedDataMapString, hasEncodedDataMap := mappedClaims[dataKey].(string); hasEncodedDataMap && len(encodedDataMapString) != 0 {
		var encodedB64String, encodedB64Err = base64.RawStdEncoding.DecodeString(encodedDataMapString)
		if encodedB64Err != nil {
			return c, nil, nerror.WrapOnly(encodedB64Err)
		}

		var mapDataReader = bytes.NewBuffer(encodedB64String)
		var decodedMap, decodedMapErr = jm.MapCodec.Decode(mapDataReader)
		if decodedMapErr != nil {
			return c, nil, nerror.WrapOnly(decodedMapErr)
		}

		c.Data = decodedMap
	}

	var sessionId, hasSessionId = mappedClaims[sessionIdKey].(string)
	if !hasSessionId {
		return c, nil, nerror.New("claims has no sessionId")
	}

	c.SessionId = sessionId

	var accessId, hasAccessId = mappedClaims[accessIdKey].(string)
	if !hasAccessId {
		return c, nil, nerror.New("claims has no accessId")
	}

	var accessXid, accessXidErr = nxid.FromString(accessId)
	if accessXidErr != nil {
		return c, nil, nerror.WrapOnly(accessXidErr)
	}

	c.AccessId = accessXid

	var accessKey = jm.formatAccessId(accessId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Get(accessKey)
	if getUserIdErr != nil {
		return c, nil, nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)

	var refreshId, hasRefreshId = mappedClaims[refreshIdKey].(string)
	if !hasRefreshId {
		return c, nil, nerror.New("claims has no rid key")
	}

	var dataClaimRefreshId, dataClaimRefreshIdErr = nxid.FromString(refreshId)
	if dataClaimRefreshIdErr != nil {
		return c, nil, nerror.WrapOnly(dataClaimRefreshIdErr)
	}

	var jwtIdFromClaim, hasJwtId = mappedClaims[jwtIdKey].(string)
	if !hasJwtId {
		return c, nil, nerror.New("claims has no jwt id")
	}

	var dataClaimId, dataClaimIdErr = nxid.FromString(jwtIdFromClaim)
	if dataClaimIdErr != nil {
		return c, nil, nerror.WrapOnly(dataClaimRefreshIdErr)
	}

	var userIdFromClaim, hasUserId = mappedClaims["aud"].(string)
	if !hasUserId {
		return c, nil, nerror.New("claims has no audience")
	}

	if userIdFromClaim != userId {
		return c, nil, nerror.New("claims userId is not valid")
	}

	var jwtIssuer, hasJwtIssuer = mappedClaims["iss"].(string)
	if !hasJwtIssuer {
		return c, nil, nerror.New("claims has no issuer")
	}

	if jwtIssuer != jm.Issuer {
		return c, nil, nerror.New("claims issuer is not valid")
	}

	var expirationTime, hasExpirationTime = mappedClaims["exp"].(int64)
	if !hasExpirationTime {
		if floatExpr, hasFloatExpr := mappedClaims["exp"].(float64); hasFloatExpr {
			hasExpirationTime = true
			expirationTime = int64(floatExpr)
		}
	}
	if !hasExpirationTime {
		return c, nil, nerror.New("claims has no expiration time, this cant be from us")
	}

	var expirationTimeValue = time.Unix(expirationTime, 0)
	var diff = time.Since(expirationTimeValue)

	// by chance did our solid ttl fail in storage to delete?
	if diff >= 0 {
		if _, removeErr := jm.RemoveAccessId(ctx, accessId); removeErr != nil {
			return c, nil, nerror.WrapOnly(removeErr)
		}

		return c, nil, nerror.New("access token has expired")
	}

	c.UserId = userId
	c.Id = dataClaimId
	c.AccessToken = accessToken
	c.AccessExpires = expirationTime
	c.RefreshId = dataClaimRefreshId

	return c, token, nil
}

// Refresh refreshes users authentication with new access token and refresh token pair by
// using a non expired refresh token to recreate associated pair.
func (jm *JWTStore) Refresh(ctx context.Context, refreshToken string) (Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var logs = njson.Log(jm.Logger)

	var c Claim

	var dc DataClaim
	if decodedErr := dc.Decode(refreshToken); decodedErr != nil {
		logs.New().LError().Message("failed to decoded refresh token").Error("error", decodedErr)
		return c, nerror.WrapOnly(decodedErr)
	}

	if len(dc.RandomId) == 0 {
		return c, nerror.New("decoded DataClaim.RandomId is empty")
	}

	if dc.RefreshId.IsNil() {
		return c, nerror.New("decoded DataClaim.RefreshId is nil")
	}

	if dc.AccessId.IsNil() {
		return c, nerror.New("decoded DataClaim.AccessId is nil")
	}

	c.DataClaim = dc

	var formattedJwtDataId = jm.formatJwtData(c.Id.String())
	var jwtData, getJwtDataErr = jm.Store.Get(formattedJwtDataId)
	if getJwtDataErr != nil {
		return c, nerror.WrapOnly(getJwtDataErr)
	}

	var jwtDataMap map[string]string
	if len(jwtData) != 0 {
		var jwtDataString = nunsafe.Bytes2String(jwtData)
		var encodedB64String, encodedB64Err = base64.RawStdEncoding.DecodeString(jwtDataString)
		if encodedB64Err != nil {
			return c, nerror.WrapOnly(encodedB64Err)
		}

		var mapDataReader = bytes.NewBuffer(encodedB64String)
		var decodedMap, decodedMapErr = jm.MapCodec.Decode(mapDataReader)
		if decodedMapErr != nil {
			return c, nerror.WrapOnly(decodedMapErr)
		}

		jwtDataMap = decodedMap
	}

	// if we are able to get refreshkey then it's not expired.
	var formattedRefreshId = jm.formatRefreshId(c.RefreshId.String())
	var refreshValueBytes, getRefreshTokenErr = jm.Store.Get(formattedRefreshId)
	if getRefreshTokenErr != nil {
		return c, nerror.WrapOnly(getRefreshTokenErr)
	}

	var refreshTokenValue = nunsafe.Bytes2String(refreshValueBytes)
	if refreshTokenValue != refreshToken {
		logs.New().LError().Message("failed refresh value check validation")
		return c, nerror.New("refresh value does not match expectation")
	}

	// Create new jwt claim
	var newClaimErr error
	c, newClaimErr = jm.CreateWithId(ctx, c.Id, c.SessionId, c.UserId, c.AccessId, jwtDataMap)
	if newClaimErr != nil {
		return c, nerror.WrapOnly(newClaimErr)
	}

	// it didnt fail, delete the refresh key, so its not usable
	if _, deleteErr := jm.Store.Remove(jm.formatRefreshId(c.RefreshId.String())); deleteErr != nil {
		logs.New().LError().Message("failed to delete refresh key for jwt token").Error("error", deleteErr)
		return c, nerror.WrapOnly(deleteErr)
	}

	return c, nil
}

func (jm *JWTStore) GetToken(ctx context.Context, token string) (*jwt.Token, jwt.MapClaims, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var parsedClaim, parseErr = jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return jm.GetSigningKey(t)
	})

	if parseErr != nil {
		return nil, nil, nerror.WrapOnly(parseErr)
	}

	if !parsedClaim.Valid {
		return nil, nil, nerror.New("token is not valid")
	}

	var jwtClaim = parsedClaim.Claims
	if validErr := jwtClaim.Valid(); validErr != nil {
		return nil, nil, nerror.WrapOnly(validErr)
	}

	var mappedClaim, ok = jwtClaim.(jwt.MapClaims)
	if !ok {
		return nil, nil, nerror.New("invalid jwt map claim")
	}

	return parsedClaim, mappedClaim, nil
}

// RemoveWithJwtIdAndSessionId removes both the respective jwt id and associated refresh and access id's
// related to the jwt, there by rendering all user's jwt access for this invalid.
//
// Delete this, delete both access and refresh at once.
func (jm *JWTStore) RemoveWithJwtIdAndSessionId(ctx context.Context, jwtId string, sessionId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	// if we are able to get refreshkey then it's not expired.
	var key = jm.formatJwtId(jwtId)
	var refreshIdAndAccessIdBytes, getJwtIdErr = jm.Store.Get(key)
	if getJwtIdErr != nil {
		return nerror.WrapOnly(getJwtIdErr)
	}

	var valueString = nunsafe.Bytes2String(refreshIdAndAccessIdBytes)
	var accessId, refreshId, decodeErr = jm.splitFormattedAccessIdAndRefreshId(valueString)
	if decodeErr != nil {
		return nerror.WrapOnly(decodeErr)
	}

	var refreshKey = jm.formatRefreshId(refreshId)
	var accessKey = jm.formatAccessId(accessId)
	var sessionKey = jm.formatSessionJwtId(jwtId, sessionId)

	if formatErr := jm.Store.RemoveKeys(refreshKey, accessKey, sessionKey, key); formatErr != nil {
		return nerror.WrapOnly(formatErr)
	}

	return nil
}

// RemoveJWTId removes both the respective jwt id and associated refresh and access id's
// related to the jwt, there by rendering all user's jwt access for this invalid.
//
// Delete this, delete both access and refresh at once.
func (jm *JWTStore) RemoveJwtId(ctx context.Context, jwtId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	// if we are able to get refreshkey then it's not expired.
	var key = jm.formatJwtId(jwtId)
	var refreshIdAndAccessIdBytes, getJwtIdErr = jm.Store.Get(key)
	if getJwtIdErr != nil {
		return nerror.WrapOnly(getJwtIdErr)
	}

	var valueString = nunsafe.Bytes2String(refreshIdAndAccessIdBytes)
	var accessId, refreshId, decodeErr = jm.splitFormattedAccessIdAndRefreshId(valueString)
	if decodeErr != nil {
		return nerror.WrapOnly(decodeErr)
	}

	var refreshKey = jm.formatRefreshId(refreshId)
	var accessKey = jm.formatAccessId(accessId)

	if formatErr := jm.Store.RemoveKeys(refreshKey, accessKey, key); formatErr != nil {
		return nerror.WrapOnly(formatErr)
	}

	return nil
}

// RemoveRefreshId removes a refreshId from store if it exists and return associated refresh Token.
// Doing this makes a refreshId invalid and un-usable.
func (jm *JWTStore) RemoveRefreshId(ctx context.Context, refreshId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var refreshKey = jm.formatRefreshId(refreshId)

	// if we are able to get refreshkey then it's not expired.
	var refreshToken, getUserIdErr = jm.Store.Remove(refreshKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	return nunsafe.Bytes2String(refreshToken), nil
}

// RemoveAcessId removes a refreshId from store if it exists and return associated userId.
// Doing this makes a refreshId invalid and un-usable.
func (jm *JWTStore) RemoveAccessId(ctx context.Context, accessId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var accessKey = jm.formatAccessId(accessId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Remove(accessKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)
	return userId, nil
}

func (jm *JWTStore) GetRefreshTokenById(ctx context.Context, refreshId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var refreshKey = jm.formatRefreshId(refreshId)

	// if we are able to get refreshkey then it's not expired.
	var refreshToken, getUserIdErr = jm.Store.Get(refreshKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(refreshToken)
	return userId, nil
}

func (jm *JWTStore) GetJwtDataById(ctx context.Context, id string) (map[string]string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var jwtIdKey = jm.formatJwtData(id)

	// if we are able to get refreshkey then it's not expired.
	var jwtDataString, getJwtDataErr = jm.Store.Get(jwtIdKey)
	if getJwtDataErr != nil {
		return nil, nerror.WrapOnly(getJwtDataErr)
	}

	var jwtDataMap map[string]string
	if len(jwtDataString) != 0 {
		var jwtDataString = nunsafe.Bytes2String(jwtDataString)
		var encodedB64String, encodedB64Err = base64.RawStdEncoding.DecodeString(jwtDataString)
		if encodedB64Err != nil {
			return nil, nerror.WrapOnly(encodedB64Err)
		}

		var mapDataReader = bytes.NewBuffer(encodedB64String)
		var decodedMap, decodedMapErr = jm.MapCodec.Decode(mapDataReader)
		if decodedMapErr != nil {
			return nil, nerror.WrapOnly(decodedMapErr)
		}

		jwtDataMap = decodedMap
	}
	return jwtDataMap, nil
}

func (jm *JWTStore) GetAccessIdAndRefreshIdByJwtId(ctx context.Context, jwtId string) (accessId string, refreshId string, err error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	// if we are able to get refreshkey then it's not expired.
	var key = jm.formatJwtId(jwtId)
	var refreshIdAndAccessIdBytes, getJwtIdErr = jm.Store.Get(key)
	if getJwtIdErr != nil {
		err = nerror.WrapOnly(getJwtIdErr)
		return
	}

	var valueString = nunsafe.Bytes2String(refreshIdAndAccessIdBytes)

	accessId, refreshId, err = jm.splitFormattedAccessIdAndRefreshId(valueString)
	return
}

func (jm *JWTStore) GetUserIdByAccessId(ctx context.Context, accessId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var refreshKey = jm.formatAccessId(accessId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Remove(refreshKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	return nunsafe.Bytes2String(userIdBytes), nil
}

func (jm *JWTStore) RemoveAllSessionJwt(ctx context.Context, sessionId string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var sessionPrefix = sessionId + dot
	var idList, err = jm.Store.EachKeyMatch(sessionPrefix)
	if err != nil {
		return nerror.WrapOnly(err)
	}

	var valueErr = jm.Store.RemoveKeys(idList...)
	if valueErr != nil {
		return nerror.WrapOnly(valueErr)
	}
	return nil
}

type JwtInfo struct {
	RefreshId string
	AccessId  string
}

func (jm *JWTStore) GetAllSessionJwt(ctx context.Context, sessionId string) (map[string]JwtInfo, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var sessionPrefix = sessionId + dot
	var idList, err = jm.Store.EachKeyMatch(sessionPrefix)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var valueList, valueErr = jm.Store.GetAnyKeys(idList...)
	if valueErr != nil {
		return nil, nerror.WrapOnly(valueErr)
	}

	if len(idList) != len(valueList) {
		return nil, nerror.New("expected length of keys to values to match")
	}

	var set = map[string]JwtInfo{}
	for index, id := range idList {
		var valueBytes = valueList[index]
		if len(valueBytes) == 0 {
			continue
		}

		var refreshId, accessId, splitErr = jm.splitFormattedAccessIdAndRefreshId(
			nunsafe.Bytes2String(valueBytes),
		)
		if splitErr != nil {
			return nil, nerror.WrapOnly(splitErr)
		}

		var jwtId = strings.TrimPrefix(id, sessionPrefix)
		set[jwtId] = JwtInfo{
			RefreshId: refreshId,
			AccessId:  accessId,
		}
	}
	return set, nil
}

func (jm *JWTStore) GetAllAccessIds(ctx context.Context) ([]string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var idList, err = jm.Store.EachKeyMatch(accessIdPrefix)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var decodedList = make([]string, len(idList))
	for index, id := range idList {
		decodedList[index] = strings.TrimPrefix(id, accessIdPrefix)
	}
	return decodedList, err
}

func (jm *JWTStore) GetAllRefreshIds(ctx context.Context) ([]string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var idList, err = jm.Store.EachKeyMatch(refreshIdPrefix)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var decodedList = make([]string, len(idList))
	for index, id := range idList {
		decodedList[index] = strings.TrimPrefix(id, refreshIdPrefix)
	}
	return decodedList, err
}

func (jm *JWTStore) GetAllJwtIds(ctx context.Context) ([]string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var idList, err = jm.Store.EachKeyMatch(jwtIdPrefix)
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var decodedList = make([]string, len(idList))
	for index, id := range idList {
		decodedList[index] = strings.TrimPrefix(id, jwtIdPrefix)
	}
	return decodedList, err
}

var jwtDataPrefix = "jwtData."

func (jm *JWTStore) formatJwtData(id string) string {
	return jwtDataPrefix + id
}

var jwtIdPrefix = "jwtId."

func (jm *JWTStore) formatJwtId(id string) string {
	return jwtIdPrefix + id
}

var refreshIdPrefix = "refreshId."

func (jm *JWTStore) formatRefreshId(refreshId string) string {
	return refreshIdPrefix + refreshId
}

var accessIdPrefix = "accessId."

func (jm *JWTStore) formatAccessId(accessId string) string {
	return accessIdPrefix + accessId
}

func (jm *JWTStore) formatSessionJwtId(jwtId string, sessionId string) string {
	return sessionId + dot + jwtId
}

func (jm *JWTStore) formatAccessIdAndRefreshId(accessId string, refreshId string) string {
	return accessId + dot + refreshId
}

func (jm *JWTStore) splitFormattedAccessIdAndRefreshId(joinedId string) (accessId string, refreshId string, err error) {
	var parts = strings.Split(joinedId, dot)
	if len(parts) != 2 {
		err = nerror.New("invalid number of parts of joined accessId and refreshId, expected 2")
		return
	}
	accessId = parts[0]
	refreshId = parts[1]
	return
}
