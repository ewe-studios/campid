package campid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
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
	jwtId       = "rid"
	accessIdKey = "acid"
	dot         = "."
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

type JWTCodec interface {
	Decode(r io.Reader) (Claim, error)
	Encode(w io.Writer, c Claim) error
}

type JWTConfig struct {
	Issuer                 string
	Authorizer             string
	GetNewClaim            GetSigningMethodAndKeyForClaim
	GetSigningKey          GetSigningKeyForToken
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	GetTime                TimeFunc
	Store                  nstorage.ExpirableStore
}

type JWTManufacturer struct {
	JWTConfig
	Logger njson.Logger
}

func NewJWTManufacturer(config JWTConfig) *JWTManufacturer {
	return &JWTManufacturer{
		JWTConfig: config,
	}
}

type DataClaim struct {
	Id       nxid.ID
	AccessId nxid.ID
	UserId   string
	RandomId string
	IsUsable bool // indicates if userId and RandomId are supplied and valid for use.
}

func (d *DataClaim) Decode(encodedDataClaim string) error {
	var decoded, err = base64.RawStdEncoding.DecodeString(encodedDataClaim)
	if err != nil {
		return nerror.WrapOnly(err)
	}
	var decodedParts = bytes.Split(decoded, nunsafe.String2Bytes(dot))
	if len(decodedParts) != 4 {
		return nerror.New("invalid encoded data token")
	}

	var idErr error
	d.Id, idErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[1]))
	if idErr != nil {
		return nerror.WrapOnly(idErr)
	}

	var accessIdErr error
	d.AccessId, accessIdErr = nxid.FromString(nunsafe.Bytes2String(decodedParts[2]))
	if accessIdErr != nil {
		return nerror.WrapOnly(accessIdErr)
	}

	d.UserId = nunsafe.Bytes2String(decodedParts[0])
	d.RandomId = nunsafe.Bytes2String(decodedParts[3])
	d.IsUsable = true
	return nil
}

func (d DataClaim) Encode() string {
	var token = strings.Join([]string{d.UserId, d.Id.String(), d.AccessId.String(), d.RandomId}, dot)
	return base64.RawStdEncoding.EncodeToString(nunsafe.String2Bytes(token))
}

type Claim struct {
	DataClaim
	AccessToken    string
	RefreshToken   string
	RefreshExpires int64
	AccessExpires  int64
}

func (jm JWTManufacturer) Create(ctx context.Context, userId string) (Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx

	var c Claim
	c.DataClaim.Id = nxid.New()
	c.DataClaim.AccessId = nxid.New()
	c.DataClaim.UserId = userId

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
	reMappedAccessClaim[accessIdKey] = c.AccessId
	reMappedAccessClaim["exp"] = accessExpiration.Unix()
	reMappedAccessClaim["iss"] = jm.Issuer
	reMappedAccessClaim["aud"] = userId
	reMappedAccessClaim[jwtId] = c.Id.String()

	var jwtAccessToken = jwt.NewWithClaims(signingMethodForAccess, reMappedAccessClaim)
	var accessToken, accessTokenErr = jwtAccessToken.SignedString(signingKeyForAccess)
	if accessTokenErr != nil {
		return c, nerror.WrapOnly(accessTokenErr)
	}

	c.AccessToken = accessToken

	// point the accessId id to the Id.
	if saveErr := jm.Store.SaveTTL(
		jm.formatAccessId(c.AccessId.String()),
		nunsafe.String2Bytes(userId),
		jm.AccessTokenExpiration,
	); saveErr != nil {
		return c, nerror.WrapOnly(saveErr)
	}

	// point the id to the refresh token.
	if saveErr := jm.Store.SaveTTL(
		jm.formatRefreshId(c.Id.String()),
		nunsafe.String2Bytes(c.RefreshToken),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		return c, nerror.WrapOnly(saveErr)
	}

	return c, nil
}

// VerifyAccess verifies provided accessToken returning claim extracted from the valid jwt signed
// token.
func (jm JWTManufacturer) VerifyAccess(ctx context.Context, accessToken string) (Claim, *jwt.Token, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var c Claim

	var token, mappedClaims, tokenErr = jm.GetToken(ctx, accessToken)
	if tokenErr != nil {
		return c, nil, nerror.WrapOnly(tokenErr)
	}

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

	var refreshId, hasRefreshId = mappedClaims[jwtId].(string)
	if !hasRefreshId {
		return c, nil, nerror.New("claims has no rid key")
	}

	var dataClaimId, dataClaimIdErr = nxid.FromString(refreshId)
	if dataClaimIdErr != nil {
		return c, nil, nerror.WrapOnly(dataClaimIdErr)
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

	c.AccessExpires = expirationTime
	c.UserId = userId
	c.AccessToken = accessToken
	c.DataClaim.Id = dataClaimId

	return c, token, nil
}

// Refresh refreshes users authentication with new access token and refresh token pair by
// using a non expired refresh token to recreate associated pair.
func (jm JWTManufacturer) Refresh(ctx context.Context, refreshToken string) (Claim, error) {
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

	c.DataClaim = dc

	// if we are able to get refreshkey then it's not expired.
	var refreshValueBytes, getUserIdErr = jm.Store.Get(jm.formatRefreshId(c.Id.String()))
	if getUserIdErr != nil {
		return c, nerror.WrapOnly(getUserIdErr)
	}

	var refreshValue = nunsafe.Bytes2String(refreshValueBytes)
	if refreshValue != refreshToken {
		logs.New().LError().Message("failed refresh value check validation")
		return c, nerror.New("refresh value does not match expectation")
	}

	// Create new jwt claim
	var newClaimErr error
	c, newClaimErr = jm.Create(ctx, c.UserId)
	if newClaimErr != nil {
		return c, nerror.WrapOnly(newClaimErr)
	}

	// it didnt fail, delete the refresh key, so its not usable
	if _, deleteErr := jm.Store.Remove(jm.formatRefreshId(c.Id.String())); deleteErr != nil {
		logs.New().LError().Message("failed to delete refresh key for jwt token").Error("error", deleteErr)
		return c, nerror.WrapOnly(deleteErr)
	}

	// delete access id as well if not yet removed.
	if _, deleteErr := jm.Store.Remove(jm.formatAccessId(c.AccessId.String())); deleteErr != nil {
		logs.New().LError().Message("failed to delete accessId for jwt token").Error("error", deleteErr)
	}

	return c, nil
}

func (jm JWTManufacturer) GetToken(ctx context.Context, token string) (*jwt.Token, jwt.MapClaims, error) {
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

// RemoveRefreshId removes a refreshId from store if it exists and return associated refresh Token.
// Doing this makes a refreshId invalid and un-usable.
func (jm JWTManufacturer) RemoveRefreshId(ctx context.Context, refreshId string) (string, error) {
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
func (jm JWTManufacturer) RemoveAccessId(ctx context.Context, accessId string) (string, error) {
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

	var userId = nunsafe.Bytes2String(userIdBytes)
	return userId, nil
}

func (jm JWTManufacturer) GetRefreshTokenById(ctx context.Context, refreshId string) (string, error) {
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

func (jm JWTManufacturer) GetUserIdByAccessId(ctx context.Context, accessId string) (string, error) {
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

	var userId = nunsafe.Bytes2String(userIdBytes)
	return userId, nil
}

func (jm JWTManufacturer) formatRefreshId(requestId string) string {
	return "requestId." + requestId
}

func (jm JWTManufacturer) formatAccessId(accessId string) string {
	return "accessId." + accessId
}
