package campid

import (
	"context"

	"github.com/ewe-studios/sabuhp"
)

type Authenticator interface {
	Login(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
	Register(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
	FinishAuth(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
	Logout(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
	Refresh(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
	Verify(ctx context.Context, msg sabuhp.Message) sabuhp.MessageErr
}

type PhoneValidator interface {
	Validate(phone string) error
}

type EmailValidator interface {
	Validate(email string) error
}
