package campid

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	openTracing "github.com/opentracing/opentracing-go"
)

type CSRFStore struct {
	defaultExpiration time.Duration
	Store             nstorage.ExpirableStore
}

func NewCSRFStore(store nstorage.ExpirableStore, defaultExpiration time.Duration) *CSRFStore {
	return &CSRFStore{
		Store:             store,
		defaultExpiration: defaultExpiration,
	}
}

func (cf *CSRFStore) GetOrCreateWithDur(ctx context.Context, sessionId string, dur time.Duration) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if dur <= 0 {
		dur = cf.defaultExpiration
	}

	var existingToken, err = cf.Store.Get(sessionId)
	if err == nil {
		return nunsafe.Bytes2String(existingToken), nil
	}

	var generatedCsrf, generatedCsrfErr = Bytes(15)
	if generatedCsrfErr != nil {
		return "", nerror.WrapOnly(generatedCsrfErr)
	}

	var csrfToken = hex.EncodeToString(generatedCsrf)
	var savedErr = cf.Store.SaveTTL(sessionId, nunsafe.String2Bytes(csrfToken), dur)
	if savedErr != nil {
		return "", nerror.WrapOnly(savedErr)
	}

	return csrfToken, nil
}

// GetOrCreate creates or gets existing csrf token for giving session id, the
// csrf token will expire after the default expiration time, generally, you should
// delete a csrf token on user session expiration (user logout or jwt refresh token in this case)
//
// But choose the best duration suited to your application needs to ensure not to invalidate
// other tokens.
func (cf *CSRFStore) GetOrCreate(ctx context.Context, sessionId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var existingToken, err = cf.Store.Get(sessionId)
	if err == nil {
		return nunsafe.Bytes2String(existingToken), nil
	}

	var generatedCsrf, generatedCsrfErr = Bytes(15)
	if generatedCsrfErr != nil {
		return "", nerror.WrapOnly(generatedCsrfErr)
	}

	var csrfToken = hex.EncodeToString(generatedCsrf)
	var savedErr = cf.Store.SaveTTL(sessionId, nunsafe.String2Bytes(csrfToken), cf.defaultExpiration)
	if savedErr != nil {
		return "", nerror.WrapOnly(savedErr)
	}

	return csrfToken, nil
}

func (cf *CSRFStore) GetAll(ctx context.Context) (map[string]string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var keyList, err = cf.Store.Keys()
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	var items = map[string]string{}
	var valueList, valueErr = cf.Store.GetAnyKeys(keyList...)
	if valueErr != nil {
		return nil, nerror.WrapOnly(valueErr)
	}

	for index, value := range valueList {
		var key = keyList[index]
		if len(value) == 0 {
			continue
		}
		items[key] = nunsafe.Bytes2String(value)
	}

	return items, nil
}

func (cf *CSRFStore) Delete(ctx context.Context, sessionId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var existingToken, err = cf.Store.Remove(sessionId)
	if err != nil {
		return "", nerror.WrapOnly(err)
	}

	return nunsafe.Bytes2String(existingToken), nil
}

func (cf *CSRFStore) Get(ctx context.Context, sessionId string) (string, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var existingToken, err = cf.Store.Get(sessionId)
	if err != nil {
		return "", nerror.WrapOnly(err)
	}

	return nunsafe.Bytes2String(existingToken), nil
}
