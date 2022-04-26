package campid

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"
)

var TelCoCarriers = map[string]string{
	"aliant-canada":          "@chat.wirefree.ca",
	"alltel":                 "@message.alltel.com",
	"ameritech":              "@paging.acswireless.com",
	"at&t":                   "@txt.att.net",
	"beeline-ua":             "@sms.beeline.ua",
	"bell-atlantic":          "@message.bam.com",
	"bellmobility-canada":    "@txt.bell.ca",
	"bellsouthmobility":      "@blsdcs.net",
	"blueskyfrog":            "@blueskyfrog.com",
	"boost":                  "@myboostmobile.com",
	"bpl-mobile":             "@bplmobile.com",
	"cellularsouth":          "@csouth1.com",
	"claro-brazil":           "@clarotorpedo.com.br",
	"claro-nicaragua":        "@ideasclaro,-ca.com",
	"comcast":                "@comcastpcs.textmsg.com",
	"cricket":                "@sms.mycricket.com",
	"du-arab-emirates":       "@email2sms.ae",
	"e-plus-germany":         "@smsmail.eplus.de",
	"etisalat-arab-emirates": "@email2sms.ae",
	"fido-canada":            "@fido.ca",
	"kajeet":                 "@mobile.kajeet.net",
	"koodoo":                 "@msg.koodomobile.com",
	"manitobatelecom-canada": "@text.mtsmobility.com",
	"metropcs":               "@mymetropcs.com",
	"mobinil-egypt":          "@mobinil.net",
	"mobistar-belgium":       "@mobistar.be",
	"mobitel":                "@sms.mobitel.lk",
	"movistar-spain":         "@correo.movistar.net",
	"nextel":                 "@messaging.nextel.com",
	"northerntel-canada":     "@txt.northerntelmobility.com",
	"o2-germany":             "@o2online.de",
	"o2-uk":                  "@mmail.co.uk",
	"orange-mumbai":          "@orangemail.co.in",
	"orange-netherlands":     "@sms.orange.nl",
	"orange-uk":              "@orange.net",
	"powertel":               "@ptel.net",
	"pscwireless":            "@sms.pscel.com",
	"qwest":                  "@qwestmp.com",
	"rogers-canada":          "@pcs.rogers.ca",
	"rogers-wireless":        "@pcs.rogers.com",
	"sasktel-canada":         "@sms.sasktel.ca",
	"sfr-france":             "@sfr.fr",
	"southernlink":           "@page.southernlinc.com",
	"sprint":                 "@messaging.sprintpcs.com",
	"suncom":                 "@tms.suncom.com",
	"t-mobile":               "@tmomail.net",
	"t-mobile-austria":       "@sms.t,-mobile.at",
	"t-mobile-germany":       "@gin.nl",
	"t-mobile-uk":            "@t,-mobile.uk.net",
	"telebec-canada":         "@txt.telebecmobilite.com",
	"telefonica-spain":       "@movistar.net",
	"telus-canada":           "@msg.telus.com",
	"telus-mobility":         "@msg.telus.com",
	"tracfone":               "@mmst5.tracfone.com",
	"uscellular":             "@email.uscc.net",
	"verizon":                "@vtext.com",
	"virgin":                 "@vmobl.net",
	"virgin-canada":          "@vmobile.ca",
	"vodafone-egypt":         "@vodafone.com.eg",
	"vodafone-germany":       "@vodafone,-sms.de",
	"vodafone-italy":         "@sms.vodafone.it",
	"vodafone-jp-chuugoku":   "@n.vodafone.ne.jp",
	"vodafone-jp-hokkaido":   "@d.vodafone.ne.jp",
	"vodafone-jp-hokuriko":   "@r.vodafone.ne.jp",
	"vodafone-jp-kansai":     "@k.vodafone.ne.jp",
	"vodafone-jp-kanto":      "@k.vodafone.ne.jp",
	"vodafone-jp-koushin":    "@k.vodafone.ne.jp",
	"vodafone-jp-kyuushu":    "@q.vodafone.ne.jp",
	"vodafone-jp-niigata":    "@h.vodafone.ne.jp",
	"vodafone-jp-okinawa":    "@q.vodafone.ne.jp",
	"vodafone-jp-osaka":      "@k.vodafone.ne.jp",
	"vodafone-jp-shikoku":    "@s.vodafone.ne.jp",
	"vodafone-jp-tokyo":      "@k.vodafone.ne.jp",
	"vodafone-jp-touhoku":    "@h.vodafone.ne.jp",
	"vodafone-jp-toukai":     "@h.vodafone.ne.jp",
	"vodafone-spain":         "@vodafone.es",
	"vodafone-uk":            "@sms.vodafone.net",
}

func NumberToCarrierEmail(number string, carrier string) (string, error) {
	var carrierHost, hasHost = TelCoCarriers[strings.ToLower(carrier)]
	if !hasHost {
		return "", nerror.New("%q carrier not found", carrier)
	}
	return fmt.Sprintf("%s%s", number, carrierHost), nil
}

type EmailSMS struct {
	Port     int
	User     string
	Password string
	Carrier  string
	Host     string
}

// Deliver sends giving message to target number using target telco carrier
// email delivery mechanism.
//
// fromAddr: is your email address
// number: the sets of numbers with carrier  to send desired message (e.g 51620726@sms.vodafone.net.
// message: the simple text message to be sent.
//
func (es *EmailSMS) Deliver(ctx context.Context, fromAddr string, message []byte, numberWithCarrier ...string) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var hostAddr = fmt.Sprintf("%s:%d", es.Host, es.Port)
	var smtpAuth = smtp.PlainAuth("", es.User, es.Password, es.Host)
	var sendErr = smtp.SendMail(hostAddr, smtpAuth, fromAddr, numberWithCarrier, message)
	if sendErr != nil {
		return nerror.WrapOnly(sendErr)
	}
	return nil
}
