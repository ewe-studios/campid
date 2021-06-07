package campid

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ewe-studios/sabuhp"

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

type RoleService struct {
	Codec       Codec
	Store       *RoleStore
	ActionStore *ActionStore
	Topics      sabuhp.TopicPartial
}

func (cs *RoleService) RegisterWithBus(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(DeleteRoleActionTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.DeleteActionRole))
	bus.Group(CreateRoleActionTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateActionRole))
	bus.Group(GetAllRoleActionTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetAllActionRole))

	bus.Group(DeleteRoleTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.RemoveRoleWithId))
	bus.Group(CreateRoleTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateRole))
	bus.Group(UpdateRoleTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.UpdateRole))
	bus.Group(GetRoleTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetWithId))
	bus.Group(GetAllRolesTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetAll))
	bus.Group(GetRoleWithActionTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetRoleWithAction))
	bus.Group(GetRolesWithActionsTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetRolesWithActions))
	bus.Group(GetRolesWithAnyActionTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetRolesWithAnyActions))
}

func (cs *RoleService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var records, getAllErr = cs.Store.All(ctx)
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

func (cs *RoleService) GetWithId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var id = msg.Params.Get("id")
	if len(id) == 0 {
		var getAllErr = nerror.New("id param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var records, getAllErr = cs.Store.ById(ctx, id)
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

func (cs *RoleService) CreateRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Role
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var createdGroup, updateErr = cs.Store.Add(ctx, update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, createdGroup); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(RoleCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *RoleService) UpdateRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Role
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var updateErr = cs.Store.Update(ctx, update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Params.Set("roleId", update.Id)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(RoleUpdatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *RoleService) RemoveRoleWithId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var id = msg.Params.Get("id")
	if len(id) == 0 {
		var getAllErr = nerror.New("id param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var records, getAllErr = cs.Store.RemoveById(ctx, id)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, records); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Params.Set("roleId", id)
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(RoleDeletedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *RoleService) GetRoleWithAction(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var actionName = msg.Params.Get("action")
	if len(actionName) == 0 {
		var getAllErr = nerror.New("actionName param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var records, getAllErr = cs.Store.RolesWithAction(ctx, ActionPolicy(actionName))
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

func (cs *RoleService) GetRolesWithAnyActions(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var actionSet = msg.Params.Get("actions")
	if len(actionSet) == 0 {
		var getAllErr = nerror.New("actionSet param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var actionNames []string
	if strings.Contains(actionSet, ";") {
		actionNames = strings.Split(actionSet, ";")
	}
	if strings.Contains(actionSet, ",") {
		actionNames = strings.Split(actionSet, ",")
	}

	var actions = make([]ActionPolicy, len(actionNames))

	for index, roleName := range actionNames {
		actions[index] = ActionPolicy(roleName)
	}

	var records, getAllErr = cs.Store.RolesWithAnyActions(ctx, actions...)
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

func (cs *RoleService) GetRolesWithActions(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var actionSet = msg.Params.Get("actions")
	if len(actionSet) == 0 {
		var getAllErr = nerror.New("actionSet param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var roleNames []string
	if strings.Contains(actionSet, ";") {
		roleNames = strings.Split(actionSet, ";")
	}
	if strings.Contains(actionSet, ",") {
		roleNames = strings.Split(actionSet, ",")
	}

	var actions = make([]ActionPolicy, len(roleNames))

	for index, roleName := range roleNames {
		actions[index] = ActionPolicy(roleName)
	}

	var records, getAllErr = cs.Store.RolesWithActions(ctx, actions...)
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

func (cs *RoleService) CreateActionRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var action = ActionPolicy(msg.Bytes)

	var updateErr = cs.ActionStore.Create(ctx, action)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Params.Set("action", action.String())
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(RoleActionCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *RoleService) GetAllActionRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var records, getErr = cs.ActionStore.All(ctx)
	if getErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getErr), http.StatusInternalServerError, false)
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

func (cs *RoleService) DeleteActionRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var action = ActionPolicy(msg.Bytes)

	var updateErr = cs.ActionStore.Delete(ctx, action)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Params.Set("action", action.String())
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(RoleActionDeletedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}
