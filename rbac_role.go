package campid

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/search/query"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
)

type RoleCodec interface {
	Decode(r io.Reader) (Role, error)
	Encode(w io.Writer, s Role) error
}

func CreateRoleDocumentMapping() (*mapping.DocumentMapping, error) {
	var roleMapping = bleve.NewDocumentMapping()

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	var actionPolicyMapping = bleve.NewDocumentMapping()
	roleMapping.AddSubDocumentMapping("Policies", actionPolicyMapping)

	roleMapping.AddFieldMappingsAt("Id", textField)
	roleMapping.AddFieldMappingsAt("Name", textField)

	return roleMapping, nil
}

func CreateLimitedRoleDocumentMapping() (*mapping.DocumentMapping, error) {
	var roleMapping = bleve.NewDocumentMapping()

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	roleMapping.AddFieldMappingsAt("Id", textField)
	roleMapping.AddFieldMappingsAt("Name", textField)

	return roleMapping, nil
}

// Role defines a series of Policies to be applied as
// authorization to a giving user.
type Role struct {
	Id       string
	Name     string
	Policies []ActionPolicy
}

type RoleStore struct {
	Codec   RoleCodec
	Indexer bleve.Index
	Store   nstorage.ExpirableStore
}

func NewRoleStore(store nstorage.ExpirableStore, codec RoleCodec, indexer bleve.Index) *RoleStore {
	return &RoleStore{
		Codec:   codec,
		Store:   store,
		Indexer: indexer,
	}
}

func (u *RoleStore) ById(ctx context.Context, id string) (Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userData, getErr = u.Store.Get(id)
	if getErr != nil {
		return Role{}, nerror.WrapOnly(getErr)
	}

	var decodedRole, decodeErr = u.Codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return Role{}, nerror.WrapOnly(decodeErr)
	}

	return decodedRole, nil
}

func (u *RoleStore) RemoveById(ctx context.Context, id string) (Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var removedRoleData, removeRoleErr = u.Store.Remove(id)
	if removeRoleErr != nil {
		return Role{}, nerror.WrapOnly(removeRoleErr)
	}

	var decodedRole, decodeErr = u.Codec.Decode(bytes.NewReader(removedRoleData))
	if decodeErr != nil {
		return Role{}, nerror.WrapOnly(decodeErr)
	}

	if indexDelErr := u.Indexer.Delete(decodedRole.Id); indexDelErr != nil {
		return decodedRole, nerror.WrapOnly(indexDelErr)
	}

	return decodedRole, nil
}

func (u *RoleStore) Update(ctx context.Context, updated Role) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var b strings.Builder
	var encodedErr = u.Codec.Encode(&b, updated)
	if encodedErr != nil {
		return nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.Store.Save(updated.Id, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if indexErr := u.Indexer.Index(updated.Id, updated); indexErr != nil {
		return nerror.WrapOnly(indexErr)
	}

	return nil
}

func (u *RoleStore) RolesWithAnyActions(ctx context.Context, policies ...ActionPolicy) ([]Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var queries = make([]query.Query, len(policies))
	for index, policy := range policies {
		var query = query.NewMatchQuery("Policies: " + policy.String())
		queries[index] = query
	}

	var searchQuery = bleve.NewDisjunctionQuery(queries...)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for policy")
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var roles = make([]Role, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr)
		}

		var decodedRole, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}

		roles[index] = decodedRole
	}

	return roles, nil
}

func (u *RoleStore) RolesWithActions(ctx context.Context, policies ...ActionPolicy) ([]Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var queries = make([]query.Query, len(policies))
	for index, policy := range policies {
		var query = query.NewMatchQuery("Policies: " + policy.String())
		queries[index] = query
	}

	var searchQuery = bleve.NewConjunctionQuery(queries...)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for policy")
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var roles = make([]Role, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr)
		}

		var decodedRole, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}

		roles[index] = decodedRole
	}

	return roles, nil
}

func (u *RoleStore) RolesWithAction(ctx context.Context, policy ActionPolicy) ([]Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Policies: " + string(policy))
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for policy").Add("policy", policy.String())
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var roles = make([]Role, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr).Add("policy", policy.String())
		}

		var decodedRole, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr).Add("policy", policy.String())
		}

		roles[index] = decodedRole
	}

	return roles, nil
}

func (u *RoleStore) All(ctx context.Context) ([]Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var roles = make([]Role, 0, 10)
	var readErr = u.Store.Each(func(value []byte, key string) error {
		var role, roleErr = u.Codec.Decode(bytes.NewReader(value))
		if roleErr != nil {
			return nerror.WrapOnly(roleErr)
		}

		roles = append(roles, role)
		return nil
	})

	if readErr != nil {
		return nil, nerror.WrapOnly(readErr)
	}

	return roles, nil
}

func (u *RoleStore) HasRole(ctx context.Context, roleName string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Name: " + roleName)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for phone number").
			Add("role", roleName)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (u *RoleStore) Add(ctx context.Context, data Role) (Role, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(data.Id) != 0 {
		return Role{}, nerror.New("groups Id cant be filled")
	}

	if len(data.Name) == 0 {
		return Role{}, nerror.New("groups Name cant be nil")
	}

	data.Id = nxid.New().String()

	var b strings.Builder
	var encodedErr = u.Codec.Encode(&b, data)
	if encodedErr != nil {
		return Role{}, nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.Store.Save(data.Id, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return Role{}, nerror.WrapOnly(saveErr)
	}

	if indexErr := u.Indexer.Index(data.Id, data); indexErr != nil {
		return Role{}, nerror.WrapOnly(indexErr)
	}

	return data, nil
}
