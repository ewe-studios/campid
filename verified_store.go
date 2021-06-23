package campid

import (
	"context"
	"fmt"

	"github.com/influx6/npkg/nerror"

	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"

	"github.com/influx6/npkg/nstorage"
)

const (
	verifiedStatus = "verified"
	pendingStatus  = "pending"
)

type VerifiedShop struct {
	SMS   TelCode
	Email MailCode
	Store nstorage.ExpirableStore
}

func NewVerifiedShop(sms TelCode, email MailCode, store nstorage.ExpirableStore) *VerifiedShop {
	return &VerifiedShop{
		Email: email,
		SMS:   sms,
		Store: store,
	}
}

func (ac *VerifiedShop) IsCompleted(ctx context.Context, u *User, d *Device) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var printId = fmt.Sprintf("%s:%s", d.FingerprintId, u.Pid)
	var status, getCodeErr = ac.Store.Get(printId)
	if getCodeErr != nil {
		return false, nerror.Wrap(getCodeErr, "failed to get result from store")
	}

	return string(status) == verifiedStatus, nil
}

func (ac *VerifiedShop) IsPending(ctx context.Context, u *User, d *Device) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var printId = fmt.Sprintf("%s:%s", d.FingerprintId, u.Pid)
	var status, getCodeErr = ac.Store.Get(printId)
	if getCodeErr != nil {
		return false, nerror.Wrap(getCodeErr, "failed to get result from store")
	}

	return string(status) == pendingStatus, nil
}

func (ac *VerifiedShop) Initiated(ctx context.Context, u *User, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var printId = fmt.Sprintf("%s:%s", d.FingerprintId, u.Pid)
	var status, getCodeErr = ac.Store.Exists(printId)
	if getCodeErr != nil {
		return nerror.Wrap(getCodeErr, "failed to get result from store")
	}

	if status {
		return nerror.New("verification already initiated")
	}

	var saveErr = ac.Store.Save(printId, []byte(pendingStatus))
	if saveErr != nil {
		return nerror.Wrap(saveErr, "failed to save verification status")
	}

	return nil
}

func (ac *VerifiedShop) Complete(ctx context.Context, u *User, d *Device) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var printId = fmt.Sprintf("%s:%s", d.FingerprintId, u.Pid)
	var status, getCodeErr = ac.Store.Exists(printId)
	if getCodeErr != nil {
		return nerror.Wrap(getCodeErr, "failed to get result from store")
	}

	if !status {
		return nerror.New("verification not started")
	}

	var saveErr = ac.Store.Save(printId, []byte(verifiedStatus))
	if saveErr != nil {
		return nerror.Wrap(saveErr, "failed to save verification status")
	}

	return nil
}
