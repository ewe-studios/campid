package campid

import (
	"context"
	"fmt"

	"github.com/influx6/npkg"
	"github.com/influx6/npkg/njson"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

var _ TelCode = (*TwilioTelCode)(nil)

type TwilioTelCode struct {
	Logger     njson.Logger
	Template   CodeTemplate
	AccountSid string
	AuthToken  string
	Region     string
	Edge       string
	From       string
}

func NewTwilioTel(logger njson.Logger, template CodeTemplate, accountSid, authToken string, from string) *TwilioTelCode {
	return NewTwilioTelWithRegionAndEdge(logger, template, accountSid, authToken, "", "", from)
}

func NewTwilioTelWithRegionAndEdge(logger njson.Logger, template CodeTemplate, accountSid, authToken string, region string, edge string, from string) *TwilioTelCode {
	return &TwilioTelCode{
		Logger:     logger,
		Template:   template,
		AccountSid: accountSid,
		AuthToken:  authToken,
		Region:     region,
		Edge:       edge,
		From:       from,
	}
}

func (tw *TwilioTelCode) SendToPhone(ctx context.Context, phoneNumber string, code string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var client = twilio.NewRestClient(tw.AccountSid, tw.AuthToken)
	if len(tw.Edge) != 0 {
		client.SetEdge(tw.Edge)
	}
	if len(tw.Region) != 0 {
		client.SetRegion(tw.Region)
	}

	var createMessage, createErr = tw.Template.Format(code)
	if createErr != nil {
		return nerror.WrapOnly(createErr)
	}

	var msg openapi.CreateMessageParams
	msg.SetBody(createMessage)
	msg.SetTo(phoneNumber)
	msg.SetFrom(tw.From)

	var res, sendErr = client.ApiV2010.CreateMessage(&msg)
	if sendErr != nil {
		return nerror.Wrap(sendErr, "Failed to send sms to %q", phoneNumber)
	}

	tw.Logger.Log(njson.MJSON("Send sms message with twilio", func(encoder npkg.Encoder) {
		encoder.String("phoneNumber", phoneNumber)
		encoder.Int("_level", int(npkg.INFO))

		encoder.ObjectFor("message", func(msgEncoder npkg.ObjectEncoder) {
			msgEncoder.String("status", *res.Status)
			msgEncoder.String("to", *res.To)
			msgEncoder.String("from", *res.From)
			msgEncoder.String("uri", *res.Uri)
			msgEncoder.String("accountSid", *res.AccountSid)
			msgEncoder.String("apiVersion", *res.ApiVersion)
			msgEncoder.String("body", *res.Body)
			msgEncoder.String("dateCreated", *res.DateCreated)
			msgEncoder.String("dateSent", *res.DateSent)
			msgEncoder.String("dateUpdated", *res.DateUpdated)
			msgEncoder.String("direction", *res.Direction)
			msgEncoder.Int32("errorCode", *res.ErrorCode)
			msgEncoder.String("errorMessage", *res.ErrorMessage)
			msgEncoder.String("from", *res.From)
			msgEncoder.String("messagingServiceSid", *res.MessagingServiceSid)
			msgEncoder.String("numMedia", *res.NumMedia)
			msgEncoder.String("numSegments", *res.NumSegments)
			msgEncoder.String("price", *res.Price)
			msgEncoder.String("priceUnit", *res.PriceUnit)
		})
	}))

	if 400 <= *res.ErrorCode && *res.ErrorCode <= 503 {
		return nerror.New("failed to deliver message").
			Add("errorCode", fmt.Sprintf("%d", *res.ErrorCode)).
			Add("errorMessage", *res.ErrorMessage)
	}

	return nil
}

type TwilioEmailCode struct {
	Logger   njson.Logger
	Template CodeTemplate
	APIKey   string
	FromAddr string
	Subject  string
}

func NewTwilioEmailCode(logger njson.Logger, template CodeTemplate, apiKey string, fromAddr string, subject string) *TwilioEmailCode {
	return &TwilioEmailCode{
		Logger:   logger,
		Template: template,
		APIKey:   apiKey,
		FromAddr: fromAddr,
		Subject:  subject,
	}
}

func (tw *TwilioEmailCode) SendToEmail(ctx context.Context, toAddr string, code string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var createMessage, createErr = tw.Template.Format(code)
	if createErr != nil {
		return nerror.WrapOnly(createErr)
	}

	var toEmail = mail.NewEmail("to", toAddr)
	var fromEmail = mail.NewEmail("from", tw.FromAddr)

	var message = mail.NewSingleEmail(fromEmail, tw.Subject, toEmail, "", createMessage)
	var client = sendgrid.NewSendClient(tw.APIKey)

	var sendResponse, sendErr = client.Send(message)
	if sendErr != nil {
		tw.Logger.Log(njson.MJSON("sent email message with twilio", func(encoder npkg.Encoder) {
			encoder.Error("error", sendErr)
			encoder.String("fromEmail", tw.FromAddr)
			encoder.String("authCode", code)
			encoder.String("toEmail", toAddr)
			encoder.Int("_level", int(npkg.INFO))
		}))
		return nerror.Wrap(sendErr, "failed to send verification code")
	}

	tw.Logger.Log(njson.MJSON("sent email message with twilio", func(encoder npkg.Encoder) {
		encoder.String("fromEmail", tw.FromAddr)
		encoder.String("authCode", code)
		encoder.String("toEmail", toAddr)
		encoder.Int("_level", int(npkg.INFO))
		encoder.String("response_body", sendResponse.Body)
		encoder.Int("response_statusCode", sendResponse.StatusCode)
		encoder.Object("response_headers", npkg.EncodableStringListMap(sendResponse.Headers))
	}))

	return nil
}
