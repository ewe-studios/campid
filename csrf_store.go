package campid

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/ewe-studios/sabuhp"

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

type CSRFService struct {
	Codec        Codec
	Store        *CSRFStore
	DeletedToken sabuhp.Topic
}

const sessionParamName = "sessionId"

func (cs *CSRFService) Delete(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var sessionId = msg.Params.Get(sessionParamName)
	if len(sessionId) == 0 {
		var getSessionErr = nerror.New("param %q not found in message", sessionParamName)
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getSessionErr), http.StatusBadRequest, true)
	}

	var value, deleteValErr = cs.Store.Delete(ctx, sessionId)
	if deleteValErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(deleteValErr), http.StatusBadRequest, true)
	}

	var newCraftedReply = msg.ReplyWithTopic(cs.DeletedToken)
	newCraftedReply.Bytes = []byte(value)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *CSRFService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var records, getAllErr = cs.Store.GetAll(ctx)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, records); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}
