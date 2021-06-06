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

type GroupCodec interface {
	Decode(r io.Reader) (Group, error)
	Encode(w io.Writer, s Group) error
}

func CreateGroupDocumentMapping() (*mapping.DocumentMapping, error) {
	var roleMapping, roleMappingErr = CreateLimitedRoleDocumentMapping()
	if roleMappingErr != nil {
		return nil, nerror.WrapOnly(roleMappingErr)
	}

	var groupMapping = bleve.NewDocumentMapping()

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	groupMapping.AddFieldMappingsAt("Id", textField)
	groupMapping.AddFieldMappingsAt("Name", textField)
	groupMapping.AddSubDocumentMapping("Roles", roleMapping)

	return groupMapping, nil
}

// Group embodies series of roles which are to be applied to
// a user.
type Group struct {
	Id    string
	Name  string
	Roles []Role
}

type GroupStore struct {
	Codec   GroupCodec
	Indexer bleve.Index
	Store   nstorage.ExpirableStore
}

func NewGroupStore(store nstorage.ExpirableStore, codec GroupCodec, indexer bleve.Index) *GroupStore {
	return &GroupStore{
		Codec:   codec,
		Store:   store,
		Indexer: indexer,
	}
}

func (u *GroupStore) All(ctx context.Context) ([]Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var groupCount, countErr = u.Store.Count()
	if countErr != nil {
		return nil, nerror.WrapOnly(countErr)
	}

	var groups = make([]Group, 0, groupCount)
	var getErr = u.Store.Each(func(i []byte, s string) error {
		var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(i))
		if decodeErr != nil {
			return nerror.WrapOnly(decodeErr)
		}

		groups = append(groups, decodedGroup)
		return nil
	})

	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	return groups, nil
}

func (u *GroupStore) ById(ctx context.Context, id string) (Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var groupData, getErr = u.Store.Get(id)
	if getErr != nil {
		return Group{}, nerror.WrapOnly(getErr)
	}

	var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(groupData))
	if decodeErr != nil {
		return Group{}, nerror.WrapOnly(decodeErr)
	}

	return decodedGroup, nil
}

func (u *GroupStore) RemoveById(ctx context.Context, id string) (Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}
	var removedGroupData, removeGroupErr = u.Store.Remove(id)
	if removeGroupErr != nil {
		return Group{}, nerror.WrapOnly(removeGroupErr)
	}

	var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(removedGroupData))
	if decodeErr != nil {
		return Group{}, nerror.WrapOnly(decodeErr)
	}

	if indexDelErr := u.Indexer.Delete(decodedGroup.Id); indexDelErr != nil {
		return decodedGroup, nerror.WrapOnly(indexDelErr)
	}

	return decodedGroup, nil
}

func (u *GroupStore) Update(ctx context.Context, updated Group) error {
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

func (u *GroupStore) GroupsWithAnyRoles(ctx context.Context, roleNames ...string) ([]Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(roleNames) == 0 {
		return nil, nerror.New("names of roles are required")
	}

	var queries = make([]query.Query, len(roleNames))
	for index, roleName := range roleNames {
		var cquery = query.NewMatchQuery("Roles.Name: " + roleName)
		queries[index] = cquery
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

	var roles = make([]Group, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr)
		}

		var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}

		roles[index] = decodedGroup
	}

	return roles, nil
}

func (u *GroupStore) GroupsWithRoles(ctx context.Context, roleNames ...string) ([]Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(roleNames) == 0 {
		return nil, nerror.New("names of roles are required")
	}

	var queries = make([]query.Query, len(roleNames))
	for index, roleName := range roleNames {
		var cquery = query.NewMatchQuery("Roles.Name: " + roleName)
		queries[index] = cquery
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

	var roles = make([]Group, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr)
		}

		var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr)
		}

		roles[index] = decodedGroup
	}

	return roles, nil
}

func (u *GroupStore) GroupsWithRole(ctx context.Context, roleName string) ([]Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Roles.Name:" + roleName)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for policy").Add("roleName", roleName)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found")
	}

	var roles = make([]Group, searchResult.Total)
	for index, matcher := range searchResult.Hits {
		var deviceData, getErr = u.Store.Get(matcher.ID)
		if getErr != nil {
			return nil, nerror.WrapOnly(getErr).Add("roleName", roleName)
		}

		var decodedGroup, decodeErr = u.Codec.Decode(bytes.NewReader(deviceData))
		if decodeErr != nil {
			return nil, nerror.WrapOnly(decodeErr).Add("roleName", roleName)
		}

		roles[index] = decodedGroup
	}

	return roles, nil
}

func (u *GroupStore) HasGroup(ctx context.Context, groupName string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Name: " + groupName)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for phone number").
			Add("role", groupName)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (u *GroupStore) Add(ctx context.Context, data Group) (Group, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if len(data.Id) != 0 {
		return Group{}, nerror.New("groups Id cant be filled")
	}

	if len(data.Name) == 0 {
		return Group{}, nerror.New("groups Name cant be nil")
	}

	data.Id = nxid.New().String()

	var b strings.Builder
	var encodedErr = u.Codec.Encode(&b, data)
	if encodedErr != nil {
		return Group{}, nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.Store.Save(data.Id, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return Group{}, nerror.WrapOnly(saveErr)
	}

	if indexErr := u.Indexer.Index(data.Id, data); indexErr != nil {
		return Group{}, nerror.WrapOnly(indexErr)
	}

	return data, nil
}

type GroupService struct {
	Codec  Codec
	Store  *GroupStore
	Topics sabuhp.TopicPartial
}

func (cs *GroupService) RegisterWithBus(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(GetGroupWithAnyOfRolesTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetGroupsWithAnyOfRoles))
	bus.Group(GetGroupWithRolesTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetGroupsWithRoles))
	bus.Group(GetGroupWithRoleTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetGroupsWithRole))
	bus.Group(GetGroupTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetWithId))
	bus.Group(GetAllGroupsTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetAll))
	bus.Group(UpdateGroupTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.UpdateGroup))
	bus.Group(DeleteGroupTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.RemoveGroupWithId))
	bus.Group(CreateGroupTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateGroup))
}

func (cs *GroupService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
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

func (cs *GroupService) GetWithId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
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

func (cs *GroupService) CreateGroup(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Group
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

	newCraftedReply.Topic = cs.Topics(GroupCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *GroupService) UpdateGroup(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update Group
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var updateErr = cs.Store.Update(ctx, update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(GroupUpdatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *GroupService) RemoveGroupWithId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
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
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(GroupDeletedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *GroupService) GetGroupsWithRole(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var roleName = msg.Params.Get("role")
	if len(roleName) == 0 {
		var getAllErr = nerror.New("roleName param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var records, getAllErr = cs.Store.GroupsWithRole(ctx, roleName)
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

func (cs *GroupService) GetGroupsWithAnyOfRoles(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var rolesSet = msg.Params.Get("roles")
	if len(rolesSet) == 0 {
		var getAllErr = nerror.New("rolesSet param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var roles []string
	if strings.Contains(rolesSet, ";") {
		roles = strings.Split(rolesSet, ";")
	}
	if strings.Contains(rolesSet, ",") {
		roles = strings.Split(rolesSet, ",")
	}

	var records, getAllErr = cs.Store.GroupsWithAnyRoles(ctx, roles...)
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

func (cs *GroupService) GetGroupsWithRoles(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var rolesSet = msg.Params.Get("roles")
	if len(rolesSet) == 0 {
		var getAllErr = nerror.New("rolesSet param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var roles []string
	if strings.Contains(rolesSet, ";") {
		roles = strings.Split(rolesSet, ";")
	}
	if strings.Contains(rolesSet, ",") {
		roles = strings.Split(rolesSet, ",")
	}

	var records, getAllErr = cs.Store.GroupsWithRoles(ctx, roles...)
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
