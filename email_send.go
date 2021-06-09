package campid

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"
)

var _ MailCode = (*SMTPMailCode)(nil)

type SMTPMailCode struct {
	Sender   EmailCode
	FromAddr string
	Template CodeTemplate
}

func (es *SMTPMailCode) SendToEmail(ctx context.Context, toAddr string, code string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var createMessage, createErr = es.Template.Format(code)
	if createErr != nil {
		return nerror.WrapOnly(createErr)
	}

	return es.Sender.Deliver(ctx, es.FromAddr, []byte(createMessage), toAddr)
}

type EmailCode struct {
	Port     int
	User     string
	Password string
	Host     string
	Auth     smtp.Auth // optional auth to be used if provided else PlainAuth is generated
}

// Deliver sends giving message to target number using target telco carrier
// email delivery mechanism.
//
// fromAddr: is your email address
// number: the sets of numbers with carrier  to send desired message (e.g 51620726@sms.vodafone.net.
// message: the simple text message to be sent.
//
func (es *EmailCode) Deliver(ctx context.Context, fromAddr string, message []byte, toAddrs ...string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hostAddr = fmt.Sprintf("%s:%d", es.Host, es.Port)

	var smtpAuth smtp.Auth
	if es.Auth == nil {
		smtpAuth = smtp.PlainAuth("", es.User, es.Password, es.Host)
	}

	var sendErr = smtp.SendMail(hostAddr, smtpAuth, fromAddr, toAddrs, message)
	if sendErr != nil {
		return nerror.WrapOnly(sendErr)
	}
	return nil
}
