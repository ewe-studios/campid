package email

import (
	"context"

	"github.com/influx6/sabuhp"
)

type PhoneAuth struct {
}

func (em *PhoneAuth) Register(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *PhoneAuth) Refresh(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *PhoneAuth) Callback(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *PhoneAuth) Logout(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}

func (em *PhoneAuth) Login(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) error {
	return nil
}
