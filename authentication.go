package campid

import (
	"context"

	"github.com/influx6/sabuhp"
)

type Authenticator interface {
	Register(ctx context.Context, msg *sabuhp.Message, t sabuhp.Transport) error
	Login(ctx context.Context, msg *sabuhp.Message, t sabuhp.Transport) error
	Logout(ctx context.Context, msg *sabuhp.Message, t sabuhp.Transport) error
	Callback(ctx context.Context, msg *sabuhp.Message, t sabuhp.Transport) error
	Refresh(ctx context.Context, msg *sabuhp.Message, t sabuhp.Transport) error
}
