package campid

import (
	"strings"
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
