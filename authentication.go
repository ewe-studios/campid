package campid

import (
	"context"

	"github.com/ewe-studios/sabuhp"
	"github.com/influx6/npkg/nerror"
	"github.com/nyaruka/phonenumbers"
)

type Authenticator interface {
	Login(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
	Verify(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
	Logout(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
	Refresh(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
	Register(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
	FinishAuth(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr
}

type PhoneValidator interface {
	ValidatePhone(phone string) error
}

type PhoneValidatorImpl struct {
	DefaultRegion string
}

func (ph PhoneValidatorImpl) ValidatePhone(phone string) error {
	var phoneNumber, phoneNumberErr = phonenumbers.Parse(phone, ph.DefaultRegion)
	if phoneNumberErr != nil {
		return nerror.WrapOnly(phoneNumberErr)
	}

	if phonenumbers.IsValidNumber(phoneNumber) {
		return nil
	}
	return nerror.New("invalid phone number %q provided", phone)
}

type EmailValidator interface {
	ValidateEmail(email string) error
}

type EmailValidatorImpl struct{}

func (e EmailValidatorImpl) ValidateEmail(email string) error {
	if err := ValidateEmail(email); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}
