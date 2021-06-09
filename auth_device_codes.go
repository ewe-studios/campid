package campid

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/influx6/npkg/nxid"

	"github.com/influx6/npkg/nerror"

	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"

	"github.com/influx6/npkg/nstorage"
)

type DeviceAuthCodes struct {
	SMS   TelCode
	Email MailCode
	TTL   time.Duration
	Store nstorage.ExpirableStore
}

func (ac *DeviceAuthCodes) VerifyCode(ctx context.Context, u *User, d *Device, returnedCode string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var storedCode, getCodeErr = ac.Store.Get(u.Pid)
	if getCodeErr != nil {
		return nerror.Wrap(getCodeErr, "code as expired")
	}

	var parts = strings.Split(string(storedCode), ":")
	if len(parts) < 2 {
		return nerror.Wrap(getCodeErr, "invalid code provided")
	}

	var fingerPrint, deviceCode = parts[0], parts[1]

	var providedParts = strings.Split(string(storedCode), ":")
	if len(providedParts) < 2 {
		return nerror.Wrap(getCodeErr, "invalid code provided")
	}

	var providedFingerPrint, providedDeviceCode = providedParts[0], providedParts[1]

	if deviceCode != providedDeviceCode {
		return nerror.New("invalid device code")
	}

	if fingerPrint != providedFingerPrint {
		return nerror.New("invalid device fingerprint")
	}

	return nil
}

func (ac *DeviceAuthCodes) ExpireCode(ctx context.Context, u *User) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var _, delErr = ac.Store.Remove(u.Pid)
	if delErr != nil {
		return nerror.WrapOnly(delErr)
	}

	return nil
}

func (ac *DeviceAuthCodes) SendEmailCode(ctx context.Context, u *User, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(u.Email) == 0 {
		return nerror.New("user has no attached email address")
	}

	var code, getCodeErr = ac.Store.Get(u.Pid)
	if getCodeErr == nil {
		if err := ac.Email.SendToEmail(ctx, u.Email, string(code)); err != nil {
			return nerror.WrapOnly(err)
		}
	}

	code = nxid.New().Bytes()
	var deviceCode = fmt.Sprintf("%s:%s", d.FingerprintId, code)
	if saveErr := ac.Store.SaveTTL(u.Pid, []byte(deviceCode), ac.TTL); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if err := ac.Email.SendToEmail(ctx, u.Email, string(code)); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (ac *DeviceAuthCodes) SendPhoneCode(ctx context.Context, u *User, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(u.Phone) == 0 {
		return nerror.New("user has no attached phone number")
	}

	var code, getCodeErr = ac.Store.Get(u.Pid)
	if getCodeErr == nil {
		if err := ac.SMS.SendToPhone(ctx, u.Phone, string(code)); err != nil {
			return nerror.WrapOnly(err)
		}
	}

	var deviceCode = fmt.Sprintf("%s:%s", d.FingerprintId, code)
	if saveErr := ac.Store.SaveTTL(u.Pid, []byte(deviceCode), ac.TTL); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if err := ac.SMS.SendToPhone(ctx, u.Phone, string(code)); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (ac *DeviceAuthCodes) SendCode(ctx context.Context, u *User, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(u.Email) != 0 {
		return ac.SendEmailCode(ctx, u, d)
	}
	return ac.SendPhoneCode(ctx, u, d)
}
