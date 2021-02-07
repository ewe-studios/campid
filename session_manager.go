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

type SessionManager struct {
	JwtStore     *JWTStore
	SessionStore *SessionStore
	DeviceStore  *DeviceStore
}

func NewSessionManager(store *SessionStore, jwtStore *JWTStore, deviceStore *DeviceStore) *SessionManager {
	return &SessionManager{
		SessionStore: store,
		JwtStore:     jwtStore,
		DeviceStore:  deviceStore,
	}
}

func (s *SessionManager) DistrustDevice(
	ctx context.Context,
	sessionId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForSessionId(ctx, sessionId, deviceId)
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

func (s *SessionManager) TrustDevice(
	ctx context.Context,
	sessionId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForSessionId(ctx, sessionId, deviceId)
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

func (s *SessionManager) EnableDevice(
	ctx context.Context,
	sessionId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForSessionId(ctx, sessionId, deviceId)
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

func (s *SessionManager) DisableDevice(
	ctx context.Context,
	sessionId string,
	deviceId string,
) (*Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var device, getDeviceErr = s.DeviceStore.GetDeviceForSessionId(ctx, sessionId, deviceId)
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

func (s *SessionManager) GetSessionAndJwtClaims(
	ctx context.Context,
	sessionId string,
	userId string,
) (*Session, map[string]JwtInfo, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var jwtInfoList, getDeviceErr = s.JwtStore.GetAllSessionJwt(ctx, userSession.Id)
	if getDeviceErr != nil {
		return nil, nil, nerror.WrapOnly(getDeviceErr)
	}

	return userSession, jwtInfoList, nil
}

func (s *SessionManager) GetSessionAndDevices(
	ctx context.Context,
	sessionId string,
	userId string,
) (*Session, []Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var devices, getDeviceErr = s.DeviceStore.GetAllDevicesForSessionId(ctx, userSession.Id)
	if getDeviceErr != nil {
		return nil, nil, nerror.WrapOnly(getDeviceErr)
	}

	return userSession, devices, nil
}

func (s *SessionManager) Get(
	ctx context.Context,
	sessionId string,
	userId string,
) (*Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nerror.WrapOnly(getSessionErr)
	}

	return userSession, nil
}

func (s *SessionManager) Remove(
	ctx context.Context,
	sessionId string,
	userId string,
) (*Session, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hasSession, hasErr = s.SessionStore.Has(ctx, sessionId, userId)
	if hasErr != nil {
		return nil, nerror.WrapOnly(hasErr).Add("sessionId", sessionId).Add("userId", userId)
	}

	if !hasSession {
		return nil, nerror.New("no session for giving user with id").Add("sessionId", sessionId).Add("userId", userId)
	}

	if removedAllDeviceErr := s.DeviceStore.RemoveAllDevicesForSessionId(ctx, sessionId); removedAllDeviceErr != nil {
		return nil, nerror.WrapOnly(removedAllDeviceErr)
	}

	if removedAllJwtErr := s.JwtStore.RemoveAllSessionJwt(ctx, sessionId); removedAllJwtErr != nil {
		return nil, nerror.WrapOnly(removedAllJwtErr)
	}

	var removedSession, removeErr = s.SessionStore.Remove(ctx, sessionId, userId)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	return removedSession, nil
}

func (s *SessionManager) Verify(
	ctx context.Context,
	sessionId string,
	userId string,
	accessToken string,
) (*Session, *Claim, *jwt.Token, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var newClaim, jwtToken, newClaimErr = s.JwtStore.VerifyAccess(ctx, accessToken)
	if newClaimErr != nil {
		return nil, nil, nil, nerror.WrapOnly(newClaimErr)
	}

	return userSession, &newClaim, jwtToken, nil
}

func (s *SessionManager) Refresh(
	ctx context.Context,
	sessionId string,
	userId string,
	refreshToken string,
) (*Session, *Claim, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		return nil, nil, nerror.WrapOnly(getSessionErr)
	}

	var newClaim, newClaimErr = s.JwtStore.Refresh(ctx, refreshToken)
	if newClaimErr != nil {
		return nil, nil, nerror.WrapOnly(newClaimErr)
	}

	return userSession, &newClaim, nil
}

func (s *SessionManager) Create(
	ctx context.Context,
	userId string,
	method string,
	deviceInfo DeviceInfo,
	jwtData map[string]string,
	sessionData map[string]string,
) (*Session, *Claim, *Device, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	// get the first session available for this user, generally session
	// manager as far as is the sole manager of the session store will only
	// ever create one per user.
	var userSession, getSessionErr = s.SessionStore.GetOneForUser(ctx, userId)
	if getSessionErr != nil {
		var se Session
		se.UserId = userId
		se.Method = method
		se.Meta = sessionData
		se.Created = time.Now()
		se.Updated = time.Now()
		se.Id = nxid.New().String()

		var generatedCsrf, generatedCsrfErr = Bytes(15)
		if generatedCsrfErr != nil {
			return nil, nil, nil, nerror.WrapOnly(generatedCsrfErr)
		}

		se.CsrfMessage = hex.EncodeToString(generatedCsrf)
		if saveSessionErr := s.SessionStore.Save(ctx, &se); saveSessionErr != nil {
			return nil, nil, nil, nerror.WrapOnly(saveSessionErr)
		}

		userSession = &se
	}

	// create jwt for new access
	var jwtClaim, createJwtErr = s.JwtStore.Create(ctx, userSession.Id, userId, jwtData)
	if createJwtErr != nil {
		return nil, nil, nil, nerror.WrapOnly(createJwtErr)
	}

	deviceInfo.SessionId = userSession.Id

	// create record of device but its yet enabled and validated,
	// user must give OTP or key from their email through Session.Manager.VerifyDevice
	// before it's enabled.
	var device, createDeviceErr = s.DeviceStore.Create(ctx, deviceInfo)
	if createDeviceErr != nil {
		return nil, nil, nil, nerror.WrapOnly(createDeviceErr)
	}

	return userSession, &jwtClaim, device, nil
}
