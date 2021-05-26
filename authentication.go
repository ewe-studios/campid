package campid

import (
	"context"

	"github.com/ewe-studios/sabuhp"
)

type Authenticator interface {
	Login(ctx context.Context, msg *sabuhp.Message) ([]*sabuhp.Message, error)
	Register(ctx context.Context, msg *sabuhp.Message) ([]*sabuhp.Message, error)
	Logout(ctx context.Context, msg *sabuhp.Message) ([]*sabuhp.Message, error)
	Callback(ctx context.Context, msg *sabuhp.Message) ([]*sabuhp.Message, error)
	Refresh(ctx context.Context, msg *sabuhp.Message) ([]*sabuhp.Message, error)
}

type PhoneValidator interface {
	Validate(phone string) error
}

type EmailValidator interface {
	Validate(email string) error
}
