package campid

import (
	"context"
	"fmt"
	"time"

	"github.com/influx6/npkg/nxid"

	"github.com/influx6/npkg/nerror"

	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"

	"github.com/influx6/npkg/nstorage"
)

type CodeTemplate interface {
	Format(code string) (string, error)
}

type SMSTemplateImpl struct {
	Title   string
	Website string
}

func NewSMSTemplateImpl(title string, website string) *SMSTemplateImpl {
	return &SMSTemplateImpl{Title: title, Website: website}
}

func (c SMSTemplateImpl) Format(code string) (string, error) {
	return fmt.Sprintf(`(%s) Welcome to %s, we are happy you've joined us, Please supply this verification Code: %s`, c.Website, c.Title, code), nil
}

type EmailTemplateImpl struct {
	Title   string
	Company string
	Website string
}

func NewEmailTemplateImpl(title string, company string, website string) *EmailTemplateImpl {
	return &EmailTemplateImpl{
		Title:   title,
		Company: company,
		Website: website,
	}
}

func (c EmailTemplateImpl) Format(code string) (string, error) {
	return fmt.Sprintf(`Welcome to %s (%s at %s)

We are happy you've joined us, but we need to confirm both your account.
Please supply this verification Code: 

%s
	`, c.Title, c.Company, c.Website, code), nil
}

type TelCode interface {
	SendToPhone(ctx context.Context, phoneNumber string, code string) error
}

type MailCode interface {
	SendToEmail(ctx context.Context, email string, code string) error
}

type AuthCodes struct {
	SMS   TelCode
	Email MailCode
	TTL   time.Duration
	Store nstorage.ExpirableStore
}

func NewAuthCodes(sms TelCode, email MailCode, ttl time.Duration, store nstorage.ExpirableStore) *AuthCodes {
	return &AuthCodes{
		SMS:   sms,
		Email: email,
		TTL:   ttl,
		Store: store,
	}
}

func (ac *AuthCodes) VerifyCode(ctx context.Context, u *User, returnedCode string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var storedCode, getCodeErr = ac.Store.Get(u.Pid)
	if getCodeErr != nil {
		return nerror.Wrap(getCodeErr, "code as expired")
	}

	if string(storedCode) != returnedCode {
		return nerror.New("invalid code")
	}

	return nil
}

func (ac *AuthCodes) ExpireCode(ctx context.Context, u *User) error {
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

func (ac *AuthCodes) SendEmailCode(ctx context.Context, u *User) error {
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
	if saveErr := ac.Store.SaveTTL(u.Pid, code, ac.TTL); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if err := ac.Email.SendToEmail(ctx, u.Email, string(code)); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (ac *AuthCodes) SendPhoneCode(ctx context.Context, u *User) error {
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

	code = nxid.New().Bytes()
	if saveErr := ac.Store.SaveTTL(u.Pid, code, ac.TTL); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if err := ac.SMS.SendToPhone(ctx, u.Phone, string(code)); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (ac *AuthCodes) SendCode(ctx context.Context, u *User) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(u.Email) != 0 {
		return ac.SendEmailCode(ctx, u)
	}
	return ac.SendPhoneCode(ctx, u)
}
