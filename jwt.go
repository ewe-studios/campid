package campid

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
)

const (
	refreshIdKey ="rfrid"
	accessIdKey = "acid"
)

type TimeFunc func() time.Time

func DefaultTimeFunc() time.Time {
	return time.Now()
}

// GetSigningMethodAndKeyForClaim returns a new claim modified accordingly to identify which
// signing method and key were used to sign and create this jwt. This then allows us
// to implement rotating keys.
type GetSigningMethodAndKeyForClaim func(jwt.MapClaims) (modClaims jwt.MapClaims, method jwt.SigningMethod, key interface{})


// GetSigningKeyForToken returns the key for giving token if it's a validly signed token.
type GetSigningKeyForToken func(t *jwt.Token) (key interface{}, err error)

type JWTCodec interface {
	Decode(r io.Reader) (Claim, error)
	Encode(w io.Writer, c Claim) error
}

type JWTConfig struct {
	Issuer                 string
	Authorizer             string
	Codec                  JWTCodec
	GetNewClaim GetSigningMethodAndKeyForClaim
	GetSigningKey             GetSigningKeyForToken
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	GetTime                TimeFunc
	Store                  nstorage.ExpirableStore
}

type JWTManufacturer struct {
	JWTConfig
}

func NewJWTManufacturer(config JWTConfig) *JWTManufacturer {
	return &JWTManufacturer{
		JWTConfig: config,
	}
}

type RefreshClaim struct {
	RefreshToken string
	RefreshId    string
	UserId       string
	RefreshExpires int64
	Token *jwt.Token
}

type AccessClaim struct {
	AccessToken  string
	AccessId     string
	UserId       string
	RefreshExpires int64
	AccessExpires int64
	Token *jwt.Token
}

type Claim struct {
	Refresh RefreshClaim
	Access AccessClaim
}

func (jm JWTManufacturer) Create(ctx context.Context, userId string) (Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var c Claim
	c.Refresh.RefreshId = nxid.New().String()
	c.Refresh.UserId = userId

	c.Access.AccessId = nxid.New().String()
	c.Access.UserId = userId

	var accessExpiration = jm.GetTime().Add(jm.AccessTokenExpiration)
	c.Access.AccessExpires = accessExpiration.Unix()

	var refreshExpiration = jm.GetTime().Add(jm.RefreshTokenExpiration)
	c.Refresh.RefreshExpires = refreshExpiration.Unix()

	// create claim for access token.
	var accessClaims = jwt.MapClaims{}
	accessClaims[accessIdKey] = c.Access.AccessId
	accessClaims["exp"] = accessExpiration.Unix()
	accessClaims["iss"] = jm.Issuer
	accessClaims["aud"] = userId

	var reMappedAccessClaim, signingMethodForAccess, signingKeyForAccess = jm.GetNewClaim(accessClaims)
	var jwtAccessToken = jwt.NewWithClaims(signingMethodForAccess, reMappedAccessClaim)
	var accessToken, accessTokenErr = jwtAccessToken.SignedString(signingKeyForAccess)
	if accessTokenErr != nil {
		return c, nerror.WrapOnly(accessTokenErr)
	}

	c.Access.AccessToken = accessToken
	c.Access.Token = jwtAccessToken

	// create claim for access token.
	var refreshClaims = jwt.MapClaims{}
	refreshClaims[refreshIdKey] = c.Refresh.RefreshId
	refreshClaims["exp"] = refreshExpiration.Unix()
	refreshClaims["iss"] = jm.Issuer
	refreshClaims["aud"] = userId

	var reMappedRefreshClaim, signingMethodForRefresh, signingKeyForRefresh = jm.GetNewClaim(refreshClaims)
	var jwtRefreshToken = jwt.NewWithClaims(signingMethodForRefresh, reMappedRefreshClaim)
	var refreshToken, refreshTokenErr = jwtRefreshToken.SignedString(signingKeyForRefresh)
	if refreshTokenErr != nil {
		return c, nerror.WrapOnly(refreshTokenErr)
	}

	c.Refresh.RefreshToken = refreshToken
	c.Refresh.Token = jwtRefreshToken

	var b strings.Builder
	var encodedErr = jm.Codec.Encode(&b, c)
	if encodedErr != nil {
		return c, nerror.WrapOnly(encodedErr)
	}

	// point the accessId id to the Id.
	if saveErr := jm.Store.SaveTTL(
		jm.formatAccessId(c.Access.AccessId),
		nunsafe.String2Bytes(userId),
		jm.AccessTokenExpiration,
	); saveErr != nil {
		return c, nerror.WrapOnly(saveErr)
	}

	// point the refresh id to the Id.
	if saveErr := jm.Store.SaveTTL(
		jm.formatRefreshId(c.Refresh.RefreshId),
		nunsafe.String2Bytes(userId),
		jm.RefreshTokenExpiration,
	); saveErr != nil {
		return c, nerror.WrapOnly(saveErr)
	}

	return c, nil
}

// VerifyAccess verifies provided accessToken returning claim extracted from the valid jwt signed
// token.
func (jm JWTManufacturer) VerifyAccess(ctx context.Context, accessToken string) (AccessClaim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var c AccessClaim

	var token, mappedClaims, tokenErr = jm.GetToken(ctx, accessToken)
	if tokenErr != nil {
		return c, nerror.WrapOnly(tokenErr)
	}

	var accessId, hasAccessId = mappedClaims[accessIdKey].(string)
	if !hasAccessId {
		return c, nerror.New("claims has no accessId")
	}

	var accessKey = jm.formatAccessId(accessId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Get(accessKey)
	if getUserIdErr != nil {
		return c, nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)
	var userIdFromClaim, hasUserId = mappedClaims["aud"].(string)
	if hasUserId {
		return c, nerror.New("claims has no audience")
	}

	if userIdFromClaim != userId {
		return c, nerror.New("claims userId is not valid")
	}

	var jwtIssuer, hasJwtIssuer = mappedClaims["iss"].(string)
	if !hasJwtIssuer {
		return c, nerror.New("claims has no issuer")
	}

	if jwtIssuer != jm.Issuer {
		return c, nerror.New("claims issuer is not valid")
	}

	var expirationTime, hasExpirationTime = mappedClaims["exp"].(int64)
	if !hasExpirationTime {
		return c, nerror.New("claims has no expiration time, this cant be from us")
	}

	var expirationTimeValue = time.Unix(expirationTime, 0)
	var diff = time.Since(expirationTimeValue)

	// by chance did our solid ttl fail in storage to delete?
	if diff <= 0 {
		if _, removeErr := jm.RemoveAccessId(ctx, accessId); removeErr != nil {
			return c, nerror.WrapOnly(removeErr)
		}

		return c, nerror.New("access token has expired")
	}

	c.AccessExpires = expirationTime
	c.AccessId = accessId
	c.UserId = userId
	c.AccessToken = accessToken
	c.Token = token

	return c, nil
}

// Refresh refreshes users authentication with new access token and refresh token pair by
// using a non expired refresh token to recreate associated pair.
func (jm JWTManufacturer) Refresh(ctx context.Context, refreshToken string) (Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var c Claim

	var _, mappedClaims, tokenErr = jm.GetToken(ctx, refreshToken)
	if tokenErr != nil {
		return c, nerror.WrapOnly(tokenErr)
	}

	var jwtIssuer, hasJwtIssuer = mappedClaims["iss"].(string)
	if !hasJwtIssuer {
		return c, nerror.New("claims has no issuer")
	}

	if jwtIssuer != jm.Issuer {
		return c, nerror.New("claims issuer is not valid")
	}

	var refreshId, hasRefreshId = mappedClaims[refreshIdKey].(string)
	if !hasRefreshId {
		return c, nerror.New("claims has no refreshId")
	}

	var refreshKey = jm.formatRefreshId(refreshId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Get(refreshKey)
	if getUserIdErr != nil {
		return c, nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)
	var userIdFromClaim, hasUserId = mappedClaims["aud"].(string)
	if hasUserId {
		return c, nerror.New("claims has no audience")
	}

	if userIdFromClaim != userId {
		return c, nerror.New("claims userId is not valid")
	}

	// Create new jwt claim
	var newClaimErr error
	c, newClaimErr = jm.Create(ctx, userId)
	if newClaimErr != nil {
		return c, nerror.WrapOnly(newClaimErr)
	}

	// it didnt fail, delete the refresh key, so its not usable
	if _, deleteErr := jm.Store.Remove(refreshKey); deleteErr != nil {
		return c, nerror.WrapOnly(deleteErr)
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

// RemoveRefreshId removes a refreshId from store if it exists and return associated userId.
// Doing this makes a refreshId invalid and un-usable.
func (jm JWTManufacturer) RemoveRefreshId(ctx context.Context, refreshId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var refreshKey = jm.formatRefreshId(refreshId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Remove(refreshKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)
	return userId, nil
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


func (jm JWTManufacturer) GetUserIdByRefreshId(ctx context.Context, refreshId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	_ = ctx
	var refreshKey = jm.formatRefreshId(refreshId)

	// if we are able to get refreshkey then it's not expired.
	var userIdBytes, getUserIdErr = jm.Store.Get(refreshKey)
	if getUserIdErr != nil {
		return "", nerror.WrapOnly(getUserIdErr)
	}

	var userId = nunsafe.Bytes2String(userIdBytes)
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
