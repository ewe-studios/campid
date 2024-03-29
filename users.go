package campid

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ewe-studios/sabuhp"

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
	"golang.org/x/crypto/bcrypt"
)

// Password is a credential validator for password authentication.
type Password struct {
	// Cost is the bcrypt hash repetition. Higher Cost results
	// in slower computations.
	Cost int

	// MinLength is the minimum length of a password.
	MinLength int

	// MaxLength is the maximum length of a password.
	// We enforce a maximum length to mitigate DOS attacks.
	MaxLength int
}

// HashString hashes a password for storage.
func (p *Password) HashString(password string) (string, error) {
	// bcrypt will manage its own salt
	hashBytes, err := p.Hash(password)
	if err != nil {
		return "", err
	}

	return nunsafe.Bytes2String(hashBytes), nil
}

// Hash hashes a password for storage.
func (p *Password) Hash(password string) ([]byte, error) {
	if passwordNotOk := p.OKForUser(password); passwordNotOk != nil {
		return nil, passwordNotOk
	}

	// bcrypt will manage its own salt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), p.Cost)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

// Validate validates if a submitted password is valid for a
// stored password hash.
func (p *Password) Validate(user *User, password string) error {
	bPasswdHash := []byte(user.HashedPassword)
	bPasswd := []byte(password)
	return bcrypt.CompareHashAndPassword(bPasswdHash, bPasswd)
}

// OKForUser tells us if a password meets minimum requirements to
// be set for any users.
func (p *Password) OKForUser(password string) error {
	if len(password) < p.MinLength {
		return nerror.New("password must be at least %v characters long", p.MinLength)
	}

	if len(password) > p.MaxLength {
		return nerror.New("password cannot be longer than %v characters", p.MaxLength)
	}

	return nil
}

type NewUser struct {
	FirstName  string
	LastName   string
	MiddleName string
	Email      string
	Phone      string
	Password   string
}

func (u NewUser) ToUser() User {
	return User{
		Id:         nxid.New().String(),
		MiddleName: u.MiddleName,
		FirstName:  u.FirstName,
		LastName:   u.LastName,
		Email:      u.Email,
		Phone:      u.Phone,
	}
}

func (u NewUser) Validate() nerror.ErrorStack {
	var errs = nerror.ErrorStack{}
	if len(u.Email) == 0 && len(u.Phone) == 0 {
		errs.Add("User.Email or User.Phone is required")
	}
	if len(u.FirstName) == 0 {
		errs.Add("User.FirstName is required")
	}
	if len(u.MiddleName) == 0 {
		errs.Add("User.MiddleName is required")
	}
	if len(u.LastName) == 0 {
		errs.Add("User.LastName is required")
	}
	if len(u.Password) == 0 {
		errs.Add("User.Password is required")
	}
	return errs
}

type NewUserCodec interface {
	Decode(r io.Reader) (NewUser, error)
	Encode(w io.Writer, s NewUser) error
}

type UserCreated struct {
	User User
	When time.Time
}

type User struct {
	Id             string // public id, is user or service provided.
	Pid            string // private id, provided only by the Store.
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
	Decode(r io.Reader) (User, error)
	Encode(w io.Writer, s User) error
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

	var phoneField = bleve.NewTextFieldMapping()
	phoneField.Analyzer = keyword.Name

	var booleanField = bleve.NewBooleanFieldMapping()
	booleanField.Analyzer = keyword.Name

	userMapping.AddFieldMappingsAt("Id", textField)
	userMapping.AddFieldMappingsAt("Pid", textField)
	userMapping.AddFieldMappingsAt("FirstName", textField)
	userMapping.AddFieldMappingsAt("MiddleName", textField)
	userMapping.AddFieldMappingsAt("LastName", textField)
	userMapping.AddFieldMappingsAt("Email", englishTextField)
	userMapping.AddFieldMappingsAt("Phone", phoneField)
	userMapping.AddFieldMappingsAt("EmailVerified", booleanField)
	userMapping.AddFieldMappingsAt("PhoneVerified", booleanField)

	return userMapping, nil
}

type UserStore struct {
	Codec          UserCodec
	Indexer        bleve.Index
	Store          nstorage.ExpirableStore
	EmailValidator EmailValidator
	PhoneValidator PhoneValidator
	Password       *Password
}

func NewUserStore(
	store nstorage.ExpirableStore,
	codec UserCodec,
	indexer bleve.Index,
	password *Password,
	emailValidator EmailValidator,
	phoneValidator PhoneValidator,
) *UserStore {
	return &UserStore{
		Codec:          codec,
		Store:          store,
		Indexer:        indexer,
		Password:       password,
		EmailValidator: emailValidator,
		PhoneValidator: phoneValidator,
	}
}

// GetAll returns all users stored within Store.
func (s *UserStore) GetAll(ctx context.Context) ([]User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var users []User
	var err = s.Store.Each(func(content []byte, key string) error {
		var reader = bytes.NewBuffer(content)
		var zone, decodeErr = s.Codec.Decode(reader)
		if decodeErr != nil {
			return nerror.WrapOnly(decodeErr)
		}
		users = append(users, zone)
		return nil
	})
	if err != nil {
		return nil, nerror.WrapOnly(err)
	}
	return users, nil
}

func (u *UserStore) ById(ctx context.Context, id string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userPid, getIdErr = u.Store.Get(id)
	if getIdErr != nil {
		return nil, nerror.WrapOnly(getIdErr)
	}

	var userData, getErr = u.Store.Get(nunsafe.Bytes2String(userPid))
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) ByPid(ctx context.Context, pid string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userData, getErr = u.Store.Get(pid)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) ByEmail(ctx context.Context, email string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Email:" + email)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for email").Add("email", email)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("email", email)
	}

	var firstMatch = searchResult.Hits[0]
	var userData, getErr = u.Store.Get(firstMatch.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) ByPhone(ctx context.Context, phone string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var searchQuery = query.NewMatchQuery("Phone:" + phone)
	var req = bleve.NewSearchRequest(searchQuery)
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return nil, nerror.Wrap(searchErr, "searching for phone number").Add("phone", phone)
	}

	if searchResult.Total == 0 {
		return nil, nerror.New("not found").Add("phone", phone)
	}

	var firstMatch = searchResult.Hits[0]
	var userData, getErr = u.Store.Get(firstMatch.ID)
	if getErr != nil {
		return nil, nerror.WrapOnly(getErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(userData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) RemoveById(ctx context.Context, id string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var removedUserPid, removeErr = u.Store.Remove(id)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	var userPid = nunsafe.Bytes2String(removedUserPid)
	var removedUserData, removeUserErr = u.Store.Remove(userPid)
	if removeUserErr != nil {
		return nil, nerror.WrapOnly(removeUserErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(removedUserData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	if indexDelErr := u.Indexer.Delete(decodedUser.Pid); indexDelErr != nil {
		return &decodedUser, nerror.WrapOnly(indexDelErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) RemoveByPid(ctx context.Context, pid string) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var removedUserData, removeErr = u.Store.Remove(pid)
	if removeErr != nil {
		return nil, nerror.WrapOnly(removeErr)
	}

	var decodedUser, decodeErr = u.Codec.Decode(bytes.NewReader(removedUserData))
	if decodeErr != nil {
		return nil, nerror.WrapOnly(decodeErr)
	}

	var _, removeIdErr = u.Store.Remove(decodedUser.Id)
	if removeIdErr != nil {
		return nil, nerror.WrapOnly(removeIdErr)
	}

	if indexDelErr := u.Indexer.Delete(decodedUser.Pid); indexDelErr != nil {
		return &decodedUser, nerror.WrapOnly(indexDelErr)
	}

	return &decodedUser, nil
}

func (u *UserStore) Update(ctx context.Context, updated *User) error {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var currentUserPid, getPidErr = u.Store.Get(updated.Id)
	if getPidErr != nil {
		return nerror.WrapOnly(getPidErr)
	}

	if updated.Pid != nunsafe.Bytes2String(currentUserPid) {
		return nerror.New("user's updated pid do not match with update")
	}

	var b strings.Builder
	var encodedErr = u.Codec.Encode(&b, *updated)
	if encodedErr != nil {
		return nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.Store.Save(updated.Pid, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nerror.WrapOnly(saveErr)
	}

	if indexErr := u.Indexer.Index(updated.Pid, updated); indexErr != nil {
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
	var searchResult, searchErr = u.Indexer.Search(req)
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
	var searchResult, searchErr = u.Indexer.Search(req)
	if searchErr != nil {
		return false, nerror.Wrap(searchErr, "searching for phone number").Add("phone", phone)
	}

	if searchResult.Total > 0 {
		return true, nil
	}
	return false, nil
}

func (u *UserStore) Create(ctx context.Context, data User) (*User, error) {
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
	var encodedErr = u.Codec.Encode(&b, data)
	if encodedErr != nil {
		return nil, nerror.WrapOnly(encodedErr)
	}

	if saveErr := u.Store.Save(data.Pid, nunsafe.String2Bytes(b.String())); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	// point the public id to the pid.
	if saveErr := u.Store.Save(data.Id, nunsafe.String2Bytes(data.Pid)); saveErr != nil {
		return nil, nerror.WrapOnly(saveErr)
	}

	if indexErr := u.Indexer.Index(data.Pid, data); indexErr != nil {
		return nil, nerror.WrapOnly(indexErr)
	}

	return &data, nil
}

func (u *UserStore) Register(ctx context.Context, newUser NewUser) (*User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var validateErr = newUser.Validate()
	if validateErr != nil {
		return nil, nerror.WrapOnly(validateErr.Err())
	}

	if len(newUser.Email) != 0 {
		if validateEmailErr := u.EmailValidator.ValidateEmail(newUser.Email); validateEmailErr != nil {
			return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(validateEmailErr), http.StatusBadRequest, true)
		}
	}

	if len(newUser.Phone) != 0 {
		if validatePhoneErr := u.PhoneValidator.ValidatePhone(newUser.Phone); validatePhoneErr != nil {
			return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(validatePhoneErr), http.StatusBadRequest, true)
		}
	}

	var hasUser bool
	var hasUserErr error
	if len(newUser.Email) != 0 && len(newUser.Phone) == 0 {
		hasUser, hasUserErr = u.HasEmail(ctx, newUser.Phone)
	}

	if len(newUser.Email) == 0 && len(newUser.Phone) != 0 {
		hasUser, hasUserErr = u.HasPhone(ctx, newUser.Phone)
	}

	if hasUserErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(hasUserErr), http.StatusBadRequest, true)
	}

	if hasUser {
		var existingUserErr ExistingUserErr
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(existingUserErr), http.StatusBadRequest, true)
	}

	var hashedPassword, hashedPasswordErr = u.Password.Hash(newUser.Password)
	if hashedPasswordErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(hashedPasswordErr), http.StatusBadRequest, true)
	}

	var userData = newUser.ToUser()
	userData.HashedPassword = nunsafe.Bytes2String(hashedPassword)

	var createdUser, failedCreateUserErr = u.Create(ctx, userData)
	if failedCreateUserErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(failedCreateUserErr), http.StatusInternalServerError, false)
	}

	return createdUser, nil
}

type UserService struct {
	Codec  Codec
	Store  *UserStore
	Topics sabuhp.TopicPartial
}

func (cs *UserService) RegisterBus(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(GetUserByEmailTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetUserByEmail))
	bus.Group(GetUserByPhoneTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetUserByPhone))
	bus.Group(GetAllUsersTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetAll))
	bus.Group(GetUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.GetUser))
	bus.Group(CreateUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.CreateUser))
	bus.Group(UpdateUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.UpdateUser))
	bus.Group(DeleteUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.RemoveUserById))
	bus.Group(DeleteUserByPidTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(cs.RemoveUserByPid))
}

func (cs *UserService) GetAll(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
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

func (cs *UserService) GetUserByPhone(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var phone = msg.Params.Get("phone")
	if len(phone) == 0 {
		var getAllErr = nerror.New("phone param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.ByPhone(ctx, phone)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *UserService) GetUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.ById(ctx, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *UserService) GetUserByEmail(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var email = msg.Params.Get("email")
	if len(email) == 0 {
		var getAllErr = nerror.New("email param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.ById(ctx, email)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *UserService) GetForById(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var id = msg.Params.Get("id")
	if len(id) == 0 {
		var getAllErr = nerror.New("id param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.ById(ctx, id)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *UserService) GetForByPid(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var pid = msg.Params.Get("pid")
	if len(pid) == 0 {
		var getAllErr = nerror.New("pid param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.ByPid(ctx, pid)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

func (cs *UserService) RemoveUserByPid(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var pid = msg.Params.Get("pid")
	if len(pid) == 0 {
		var getAllErr = nerror.New("pid param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.RemoveByPid(ctx, pid)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeletedUserTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *UserService) RemoveUserById(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var id = msg.Params.Get("id")
	if len(id) == 0 {
		var getAllErr = nerror.New("id param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.RemoveById(ctx, id)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.Params.Set("id", id)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeletedUserTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *UserService) RemoveUserByUserId(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		var getAllErr = nerror.New("userId param not found")
		return sabuhp.WrapErrWithStatusCode(getAllErr, http.StatusBadRequest, false)
	}

	var record, getAllErr = cs.Store.RemoveById(ctx, userId)
	if getAllErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getAllErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, record); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.Params.Set("userId", userId)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(DeletedUserTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *UserService) UpdateUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update User
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var updateErr = cs.Store.Update(ctx, &update)
	if updateErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(updateErr), http.StatusInternalServerError, false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := cs.Codec.Encode(buffer, update); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(msg.Topic.ReplyTopic())
	newCraftedReply.Bytes = CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	newCraftedReply.Topic = cs.Topics(UserUpdatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}
func (cs *UserService) CreateUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update User
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var createdGroup, updateErr = cs.Store.Create(ctx, update)
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

	newCraftedReply.Topic = cs.Topics(UserCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}

func (cs *UserService) RegisterUser(ctx context.Context, msg sabuhp.Message, tr sabuhp.Transport) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var readBuffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&readBuffer)

	var update NewUser
	if decodedErr := cs.Codec.Decode(readBuffer, &update); decodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodedErr), http.StatusBadRequest, true)
	}

	var createdGroup, updateErr = cs.Store.Register(ctx, update)
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

	newCraftedReply.Topic = cs.Topics(UserCreatedTopic)
	tr.ToBoth(newCraftedReply)
	return nil
}
