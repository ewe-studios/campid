package campid

import (
	"bytes"
	"net"
	"strings"

	"github.com/ewe-studios/sabuhp"
	"github.com/influx6/npkg/nerror"
)

func CopyBytes(b []byte) []byte {
	var m = make([]byte, len(b))
	copy(m, b)
	return m
}

func CopyBufferBytes(b *bytes.Buffer) []byte {
	return CopyBytes(b.Bytes())
}

func CopyValueBufferBytes(b bytes.Buffer) []byte {
	return CopyBytes(b.Bytes())
}

func WriteDeviceToMessage(msg *sabuhp.Message, d Device) {
	var deviceData = strings.Join([]string{
		d.FingerprintId, d.ZoneId, d.UserId,
	}, ":")

	msg.Headers.Set(DeviceHeaderName, deviceData)
	msg.Cookies = append(msg.Cookies, sabuhp.Cookie{
		Name:     DeviceCookieName,
		Value:    deviceData,
		MaxAge:   365,
		HttpOnly: false,
	})
}

type VerifyAccess struct {
	AccessToken  string
	RefreshToken string
}

func (v VerifyAccess) ValidateRefresh() error {
	if len(v.RefreshToken) == 0 {
		return nerror.New("VerifiedAccess.RefreshToken is required")
	}
	return nil
}

func (v VerifyAccess) ValidateAccess() error {
	if len(v.AccessToken) == 0 {
		return nerror.New("VerifiedAccess.AccessToken is required")
	}
	return nil
}

func (v VerifyAccess) ValidateAll() error {
	if err := v.ValidateRefresh(); err != nil {
		return err
	}
	if err := v.ValidateAccess(); err != nil {
		return err
	}
	return nil
}

func ExtractJwtAuth(msg *sabuhp.Message) (VerifyAccess, error) {
	var login VerifyAccess

	login.AccessToken = msg.Params.Get("accessToken")
	login.RefreshToken = msg.Params.Get("refreshToken")

	if len(login.AccessToken) == 0 {
		var accessCookie *sabuhp.Cookie
		var refreshCookie *sabuhp.Cookie
		for _, cookie := range msg.Cookies {
			if accessCookie != nil && refreshCookie != nil {
				break
			}
			if cookie.Name == "refreshToken" {
				refreshCookie = &cookie
				continue
			}
			if cookie.Name == "accessToken" {
				accessCookie = &cookie
				continue
			}
		}

		if accessCookie != nil {
			login.AccessToken = accessCookie.Value
		}
		if refreshCookie != nil {
			login.RefreshToken = refreshCookie.Value
		}
	}

	var refreshHeader = msg.Headers.Get(RefreshHeader)
	if len(login.RefreshToken) == 0 && len(refreshHeader) != 0 {
		login.RefreshToken = refreshHeader
	}

	var authHeader = msg.Headers.Get(AuthHeader)
	if len(login.AccessToken) == 0 && len(authHeader) != 0 {
		var authorizationHeader = strings.TrimPrefix(authHeader, "Bearer")
		login.AccessToken = strings.TrimSpace(authorizationHeader)
	}

	if len(login.AccessToken) == 0 && len(login.RefreshToken) == 0 {
		return login, nerror.New("no authorization info found")
	}

	return login, nil
}

func ExtractDeviceInfo(msg *sabuhp.Message) (DeviceInfo, error) {
	var info DeviceInfo
	info.IP = net.ParseIP(msg.IP)

	var foundAgent bool
	var agentValue = msg.Headers.Get(UserAgentHeader)
	if len(agentValue) != 0 {
		foundAgent = true
		var parsedAgent, parsedAgentErr = ParseAgent(agentValue)
		if parsedAgentErr != nil {
			return info, nerror.WrapOnly(parsedAgentErr)
		}

		info.Agent = parsedAgent
	}

	var foundHeader bool
	var headerValue = msg.Headers.Get(DeviceHeaderName)
	if len(headerValue) != 0 {
		foundHeader = true
		var deviceData = strings.Split(headerValue, ":")
		if len(deviceData) != 3 {
			return info, nerror.New("Device header %s data does not match expected format", DeviceHeaderName)
		}

		info.FingerprintId = deviceData[0]
		info.ZoneId = deviceData[1]
		info.UserId = deviceData[2]
	}

	var foundCookie bool
	var deviceCookie, findCookieErr = FindCookie(DeviceCookieName, msg.Cookies)
	if findCookieErr == nil {
		foundCookie = true
		var deviceData = strings.Split(deviceCookie.Value, ":")
		if len(deviceData) != 3 {
			return info, nerror.New("Device cookie data does not match expected format")
		}

		info.FingerprintId = deviceData[0]
		info.ZoneId = deviceData[1]
		info.UserId = deviceData[2]
	}

	var fingerprintCookie, fingerprintCookieErr = FindCookie(DeviceFingerprintCookieName, msg.Cookies)
	if fingerprintCookieErr == nil {
		foundCookie = true
		info.FingerprintId = fingerprintCookie.Value
	}

	if !foundAgent && !foundHeader && !foundCookie {
		return info, nerror.New("")
	}

	return info, nil
}

func FindCookie(cookieName string, cookies []sabuhp.Cookie) (sabuhp.Cookie, error) {
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			return cookie, nil
		}
	}
	return sabuhp.Cookie{}, nerror.New("failed to find %q", cookieName)
}
