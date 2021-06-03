package campid

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
)

type UserZoneManager struct {
	JwtStore    *JWTStore
	ZoneStore   *ZoneStore
	DeviceStore *DeviceStore
}

func NewZoneManager(store *ZoneStore, jwtStore *JWTStore, deviceStore *DeviceStore) *UserZoneManager {
	return &UserZoneManager{
		ZoneStore:   store,
		JwtStore:    jwtStore,
		DeviceStore: deviceStore,
	}
}

func (s *UserZoneManager) DistrustDevice(
	ctx context.Context,
	zoneId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForZoneId(ctx, zoneId, deviceId)
	if getDeviceErr != nil {
		return nil, nerror.WrapOnly(getDeviceErr)
	}

	device.IsTrusted = false

	var updatedDevice, updateErr = s.DeviceStore.Update(ctx, device)
	if updateErr != nil {
		return nil, nerror.WrapOnly(updateErr)
	}
	return updatedDevice, nil
}

func (s *UserZoneManager) TrustDevice(
	ctx context.Context,
	zoneId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForZoneId(ctx, zoneId, deviceId)
	if getDeviceErr != nil {
		return nil, nerror.WrapOnly(getDeviceErr)
	}

	device.IsTrusted = true

	var updatedDevice, updateErr = s.DeviceStore.Update(ctx, device)
	if updateErr != nil {
		return nil, nerror.WrapOnly(updateErr)
	}
	return updatedDevice, nil
}

func (s *UserZoneManager) EnableDevice(
	ctx context.Context,
	zoneId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForZoneId(ctx, zoneId, deviceId)
	if getDeviceErr != nil {
		return nil, nerror.WrapOnly(getDeviceErr)
	}

	device.IsEnabled = true

	var updatedDevice, updateErr = s.DeviceStore.Update(ctx, device)
	if updateErr != nil {
		return nil, nerror.WrapOnly(updateErr)
	}
	return updatedDevice, nil
}

func (s *UserZoneManager) DisableDevice(
	ctx context.Context,
	zoneId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForZoneId(ctx, zoneId, deviceId)
	if getDeviceErr != nil {
		return nil, nerror.WrapOnly(getDeviceErr)
	}

	device.IsEnabled = false

	var updatedDevice, updateErr = s.DeviceStore.Update(ctx, device)
	if updateErr != nil {
		return nil, nerror.WrapOnly(updateErr)
	}
	return updatedDevice, nil
}

func (s *UserZoneManager) GetSessionAndJwtClaims(
	ctx context.Context,
	zoneId string,
	userId string,
) (*Zone, map[string]JwtInfo, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var jwtInfoList, getDeviceErr = s.JwtStore.GetAllSessionJwt(ctx, userSession.Id)
	if getDeviceErr != nil {
		return nil, nil, nerror.WrapOnly(getDeviceErr)
	}

	return userSession, jwtInfoList, nil
}

func (s *UserZoneManager) GetSessionAndDevices(
	ctx context.Context,
	zoneId string,
	userId string,
) (*Zone, []Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var devices, getDeviceErr = s.DeviceStore.GetAllDevicesForZoneId(ctx, userSession.Id)
	if getDeviceErr != nil {
		return nil, nil, nerror.WrapOnly(getDeviceErr)
	}

	return userSession, devices, nil
}

func (s *UserZoneManager) Get(
	ctx context.Context,
	userId string,
) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.ZoneStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nerror.WrapOnly(getSessionErr)
	}

	return userSession, nil
}

func (s *UserZoneManager) DeleteAllDevices(
	ctx context.Context,
	zoneId string,
	userId string,
) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hasSession, hasErr = s.ZoneStore.Has(ctx, zoneId, userId)
	if hasErr != nil {
		return nerror.WrapOnly(hasErr).Add("zoneId", zoneId).Add("userId", userId)
	}

	if !hasSession {
		return nerror.New("no session for giving user with id").Add("zoneId", zoneId).Add("userId", userId)
	}

	if removedAllDeviceErr := s.DeviceStore.RemoveAllDevicesForZoneId(ctx, zoneId); removedAllDeviceErr != nil {
		return nerror.WrapOnly(removedAllDeviceErr)
	}

	return nil
}

func (s *UserZoneManager) DeleteJwtSessions(
	ctx context.Context,
	zoneId string,
	userId string,
) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hasSession, hasErr = s.ZoneStore.Has(ctx, zoneId, userId)
	if hasErr != nil {
		return nerror.WrapOnly(hasErr).Add("zoneId", zoneId).Add("userId", userId)
	}

	if !hasSession {
		return nerror.New("no session for giving user with id").Add("zoneId", zoneId).Add("userId", userId)
	}

	if removedAllJwtErr := s.JwtStore.RemoveAllZoneJwt(ctx, zoneId); removedAllJwtErr != nil {
		return nerror.WrapOnly(removedAllJwtErr)
	}

	return nil
}

func (s *UserZoneManager) DeleteAllForUser(
	ctx context.Context,
	zoneId string,
	userId string,
) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hasSession, hasErr = s.ZoneStore.Has(ctx, zoneId, userId)
	if hasErr != nil {
		return nil, nerror.WrapOnly(hasErr).Add("zoneId", zoneId).Add("userId", userId)
	}

	if !hasSession {
		return nil, nerror.New("no session for giving user with id").Add("zoneId", zoneId).Add("userId", userId)
	}

	if removedAllDeviceErr := s.DeviceStore.RemoveAllDevicesForZoneId(ctx, zoneId); removedAllDeviceErr != nil {
		return nil, nerror.WrapOnly(removedAllDeviceErr)
	}

	if removedAllJwtErr := s.JwtStore.RemoveAllZoneJwt(ctx, zoneId); removedAllJwtErr != nil {
		return nil, nerror.WrapOnly(removedAllJwtErr)
	}

	var removedSession, removeErr = s.ZoneStore.Remove(ctx, zoneId, userId)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	return removedSession, nil
}

func (s *UserZoneManager) Verify(
	ctx context.Context,
	zoneId string,
	userId string,
	accessToken string,
) (*Zone, *Claim, *jwt.Token, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var newClaim, jwtToken, newClaimErr = s.JwtStore.VerifyAccess(ctx, accessToken)
	if newClaimErr != nil {
		return nil, nil, nil, nerror.WrapOnly(newClaimErr)
	}

	return userSession, &newClaim, jwtToken, nil
}

func (s *UserZoneManager) Refresh(
	ctx context.Context,
	zoneId string,
	userId string,
	refreshToken string,
) (*Zone, *Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var newClaim, newClaimErr = s.JwtStore.Refresh(ctx, refreshToken)
	if newClaimErr != nil {
		return nil, nil, nerror.WrapOnly(newClaimErr)
	}

	return userSession, &newClaim, nil
}

func (s *UserZoneManager) CreateZoneWithJwtAndDevice(
	ctx context.Context,
	userId string,
	method string,
	deviceInfo DeviceInfo,
	jwtData map[string]string,
	sessionData map[string]string,
) (*Zone, *Claim, *Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userZone, getZoneErr = s.CreateZone(ctx, userId, method, sessionData)
	if getZoneErr != nil {
		return nil, nil, nil, nerror.WrapOnly(getZoneErr)
	}

	// create jwt for new access
	var jwtClaim, createJwtErr = s.JwtStore.Create(ctx, userZone.Id, userId, jwtData)
	if createJwtErr != nil {
		return nil, nil, nil, nerror.WrapOnly(createJwtErr)
	}

	deviceInfo.ZoneId = userZone.Id

	// create record of device but its yet enabled and validated,
	// user must give OTP or key from their email through Zone.Manager.VerifyDevice
	// before it's enabled.
	var device, createDeviceErr = s.DeviceStore.Create(ctx, deviceInfo)
	if createDeviceErr != nil {
		return nil, nil, nil, nerror.WrapOnly(createDeviceErr)
	}

	return userZone, &jwtClaim, device, nil
}

func (s *UserZoneManager) CreateZone(
	ctx context.Context,
	userId string,
	method string,
	sessionData map[string]string,
) (*Zone, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	if userZone, getZoneErr := s.ZoneStore.GetOneForUser(ctx, userId); getZoneErr == nil {
		return userZone, nil
	}

	var se Zone
	se.UserId = userId
	se.Method = method
	se.Meta = sessionData
	se.Created = time.Now()
	se.Updated = time.Now()
	se.Id = nxid.New().String()

	var generatedCsrf, generatedCsrfErr = Bytes(15)
	if generatedCsrfErr != nil {
		return nil, nerror.WrapOnly(generatedCsrfErr)
	}

	se.CsrfMessage = hex.EncodeToString(generatedCsrf)
	if saveSessionErr := s.ZoneStore.Save(ctx, &se); saveSessionErr != nil {
		return nil, nerror.WrapOnly(saveSessionErr)
	}

	return &se, nil
}

func (s *UserZoneManager) AddJwtSessionToZone(
	ctx context.Context,
	zoneId string,
	userId string,
	jwtData map[string]string,
) (*Zone, *Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	// create jwt for new access
	var jwtClaim, createJwtErr = s.JwtStore.Create(ctx, userSession.Id, userId, jwtData)
	if createJwtErr != nil {
		return nil, nil, nerror.WrapOnly(createJwtErr)
	}

	return userSession, &jwtClaim, nil
}

func (s *UserZoneManager) AddDeviceToZone(
	ctx context.Context,
	zoneId string,
	userId string,
	deviceInfo DeviceInfo,
) (*Zone, *Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.ZoneStore.GetById(ctx, zoneId, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	deviceInfo.ZoneId = userSession.Id

	// create record of device but its yet enabled and validated,
	// user must give OTP or key from their email through Zone.Manager.VerifyDevice
	// before it's enabled.
	var device, createDeviceErr = s.DeviceStore.Create(ctx, deviceInfo)
	if createDeviceErr != nil {
		return nil, nil, nerror.WrapOnly(createDeviceErr)
	}

	return userSession, device, nil
}
