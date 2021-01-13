package campid

import (
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/v2/analysis/lang/en"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/search/query"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nstorage"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	"github.com/influx6/npkg/nxid"
	openTracing "github.com/opentracing/opentracing-go"
)

type User struct {
	Id             string // public id, is user or service provided.
	Pid            string // private id, provided only by the store.
	FirstName      string
	LastName       string
	MiddleName     string
	Email          string
	Phone          string
	HashedPassword string
	EmailVerified  bool
	PhoneVerified  bool
}

// PublicSafeUser returns a version of the user object which
// can be shared publicly, nulling any sensitive information.
func (u *User) PublicSafeUser() User {
	var un = *u
	un.Pid = ""
	un.HashedPassword = ""
	return un
}

func (u *User) ValidateEmailVerified() error {
	if !u.EmailVerified {
		return nerror.New("User.Email is not yet verified")
	}
	return nil
}

func (u *User) ValidatePhoneVerified() error {
	if !u.PhoneVerified {
		return nerror.New("User.Phone is not yet verified")
	}
	return nil
}

func (u *User) ValidateVerified() error {
	if !u.EmailVerified && !u.PhoneVerified {
		return nerror.New("user is not yet verified")
	}
	return nil
}

func (u *User) ValidateCreated() error {
	var errs = u.validate()
	if len(u.Pid) == 0 {
		errs.Add("User.Pid is required")
	}
	return errs.Err()
}

func (u *User) Validate() error {
	validate := u.validate()
	return validate.Err()
}

func (u *User) validate() nerror.ErrorStack {
	var errs = nerror.ErrorStack{}
	if len(u.Id) == 0 {
		errs.Add("User.Id is required")
	}
	if len(u.FirstName) == 0 {
		errs.Add("User.FirstName is required")
	}
	if len(u.Phone) == 0 {
		errs.Add("User.Phone is required")
	}
	if len(u.Email) == 0 {
		errs.Add("User.Email is required")
	}
	if len(u.MiddleName) == 0 {
		errs.Add("User.MiddleName is required")
	}
	if len(u.LastName) == 0 {
		errs.Add("User.LastName is required")
	}
	return errs
}

type UserCodec interface {
	Decode(r io.Reader) (*User, error)
	Encode(w io.Writer, s *User) error
}

func CreateUserIndexMapping() (mapping.IndexMapping, error) {
	var userMapping, err = CreateUserDocumentMapping()
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}

	indexMapping := bleve.NewIndexMapping()
	indexMapping.AddDocumentMapping("User", userMapping)
	return indexMapping, nil
}

func CreateUserDocumentMapping() (*mapping.DocumentMapping, error) {
	var userMapping = bleve.NewDocumentMapping()

	var englishTextField = bleve.NewTextFieldMapping()
	englishTextField.Analyzer = en.AnalyzerName

	var textField = bleve.NewTextFieldMapping()
	textField.Analyzer = keyword.Name

	var booleanField = bleve.NewBooleanFieldMapping()
	booleanField.Analyzer = keyword.Name

	userMapping.AddFieldMappingsAt("Id", textField)
	userMapping.AddFieldMappingsAt("Pid", textField)
	userMapping.AddFieldMappingsAt("FirstName", textField)
	userMapping.AddFieldMappingsAt("MiddleName", textField)
	userMapping.AddFieldMappingsAt("LastName", textField)
	userMapping.AddFieldMappingsAt("Email", englishTextField)
	userMapping.AddFieldMappingsAt("Phone", englishTextField)
	userMapping.AddFieldMappingsAt("EmailVerified", booleanField)
	userMapping.AddFieldMappingsAt("PhoneVerified", booleanField)

	return userMapping, nil
}

type UserStore struct {
	codec   UserCodec
	indexer bleve.Index
	store   nstorage.ExpirableStore
}

func NewUserStore(store nstorage.ExpirableStore, codec UserCodec, indexer bleve.Index) *UserStore {
	return &UserStore{
		codec:   codec,
		store:   store,
		indexer: indexer,
	}
}

func (u *UserStore) ById(ctx context.Context, id string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userPid, getIdErr = u.store.Get(id)
	if getIdErr != nil {
		return nil, nerror.WrapOnly(getIdErr)
	}

	var userData, getErr = u.store.Get(nunsafe.Bytes2String(userPid))
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return decodedUser, nil
}

func (u *UserStore) ByPid(ctx context.Context, pid string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userData, getErr = u.store.Get(pid)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return decodedUser, nil
}

func (u *UserStore) ByEmail(ctx context.Context, email string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Email:" + email)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for email").Add("email", email)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("email", email)
	}

	var firstMatch = searchResult.Hits[0]
	var userData, getErr = u.store.Get(firstMatch.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return decodedUser, nil
}

func (u *UserStore) ByPhone(ctx context.Context, phone string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Phone:" + phone)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for phone number").Add("phone", phone)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("phone", phone)
	}

	var firstMatch = searchResult.Hits[0]
	var userData, getErr = u.store.Get(firstMatch.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return decodedUser, nil
}

func (u *UserStore) RemoveById(ctx context.Context, id string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var removedUserPid, removeErr = u.store.Remove(id)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	var userPid = nunsafe.Bytes2String(removedUserPid)
	var removedUserData, removeUserErr = u.store.Remove(userPid)
	if removeUserErr != nil {
		return nil, nerror.WrapOnly(removeUserErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(removedUserData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return decodedUser, nil
}

func (u *UserStore) RemoveByPid(ctx context.Context, pid string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var removedUserData, removeErr = u.store.Remove(pid)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	var decodedUser, decodeErr = u.codec.Decode(bytes.NewReader(removedUserData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	var _, removeIdErr = u.store.Remove(decodedUser.Id)
	if removeIdErr != nil {
		return nil, nerror.WrapOnly(removeIdErr)
	}

	return decodedUser, nil
}

func (u *UserStore) Update(ctx context.Context, updated *User) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var currentUserPid, getPidErr = u.store.Get(updated.Id)
	if getPidErr != nil {
		return nerror.WrapOnly(getPidErr)
	}

	if updated.Pid != nunsafe.Bytes2String(currentUserPid) {
		return nerror.New("user's updated pid do not match with update")
	}

	var b strings.Builder
	var encodedErr = u.codec.Encode(&b, updated)
	if encodedErr != nil {
		return nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.store.Save(updated.Pid, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if indexErr := u.indexer.Index(updated.Pid, updated); indexErr != nil {
		return nerror.WrapOnly(indexErr)
	}

	return nil
}

func (u *UserStore) HasEmail(ctx context.Context, email string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Email:" + email)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for email").Add("email", email)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (u *UserStore) HasPhone(ctx context.Context, phone string) (bool, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Phone:" + phone)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for phone number").Add("phone", phone)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (u *UserStore) Add(ctx context.Context, data User) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := data.Validate(); validateErr != nil {
		return nil, nerror.WrapOnly(validateErr)
	}

	// is the user pre-existing by email or phone number?
	var hasEmail, hasEmailErr = u.HasEmail(ctx, data.Email)
	if hasEmailErr != nil {
		return nil, nerror.WrapOnly(hasEmailErr)
	}

	if hasEmail {
		return nil, nerror.Wrap(hasEmailErr, "user email already exists").Add("email", data.Email)
	}

	data.Pid = nxid.New().String()

	var b strings.Builder
	var encodedErr = u.codec.Encode(&b, &data)
	if encodedErr != nil {
		return nil, nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.store.Save(data.Pid, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	// point the public id to the pid.
	if saveErr := u.store.Save(data.Id, nunsafe.String2Bytes(data.Pid)); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	if indexErr := u.indexer.Index(data.Pid, data); indexErr != nil {
		return nil, nerror.WrapOnly(indexErr)
	}

	return &data, nil
}
