package email

import (
	"context"

	"github.com/influx6/sabuhp"
)
	
type EmailAuth struct {
}

func (em *EmailAuth) Register(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *EmailAuth) Refresh(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *EmailAuth) Callback(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *EmailAuth) Logout(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *EmailAuth) Login(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}
