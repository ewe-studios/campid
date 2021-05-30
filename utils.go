package campid

import (
	"bytes"
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

func ExtractDeviceInfo(msg *sabuhp.Message) (DeviceInfo, error) {
	var info DeviceInfo

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
