package campid

import (
	"context"
	"strings"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"
)

// PolicyScope should be a namespaced dotted string of
// granula pointers for specific actions.
// e.g pages.page.add_page, pages.page.delete_page, pages.user.show_profile, pages.*
type PolicyScope string

type Permission string

const (
	ReadPermission   Permission = "READ"   // covers read singular or series of items
	WritePermission  Permission = "WRITE"  // cover create, update, put/patch
	ListPermission   Permission = "LIST"   // covers listing calls, list page, list etc
	DeletePermission Permission = "DELETE" // covers delete, destroy, remove
)

// ActionPolicy embodies the singular permission which allows a giving entity
// the capacity to perform specific action.
//
// ActionPolicy can have a grouping, a categorization that defines what category
// they are in e.g read, write, systems, ..etc
type ActionPolicy string

func (a ActionPolicy) String() string {
	return string(a)
}

func CreateActionPolicy(perm Permission, action string) string {
	return strings.Join([]string{string(perm), action}, "::")
}

type ActionStore struct {
	Store nstorage.ExpirableStore
}

func (u *ActionStore) Delete(ctx context.Context, action ActionPolicy) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if _, err := u.Store.Remove(action.String()); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (u *ActionStore) Create(ctx context.Context, action ActionPolicy) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if err := u.Store.Save(action.String(), []byte(action.String())); err != nil {
		return nerror.WrapOnly(err)
	}
	return nil
}

func (u *ActionStore) All(ctx context.Context) ([]ActionPolicy, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var actions = make([]ActionPolicy, 0, 10)
	var readErr = u.Store.Each(func(value []byte, key string) error {
		actions = append(actions, ActionPolicy(value))
		return nil
	})

	if readErr != nil {
		return nil, nerror.WrapOnly(readErr)
	}

	return actions, nil
}
