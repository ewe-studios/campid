package commonLogin

import (
	"bytes"
	"context"
	"io"
	"sync"

	"github.com/ewe-studios/campid"
	"github.com/ewe-studios/sabuhp"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	"github.com/influx6/npkg/nunsafe"
	openTracing "github.com/opentracing/opentracing-go"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

type Login struct {
	Email       string
	Phone       string
	Password    string
	IsPhone     bool
	Fingerprint string
	Method      string
}

func (el Login) Validate() error {
	if el.IsPhone && len(el.Phone) == 0 {
		return nerror.New("EmailLogin.Phone is required when EmailLogin.IsPhone is true")
	}
	if len(el.Email) == 0 && !el.IsPhone {
		return nerror.New("EmailLogin.Email is required when not using phone number")
	}
	if len(el.Password) == 0 {
		return nerror.New("EmailLogin.Password is required")
	}
	return nil
}

type LoginCodec interface {
	Decode(r io.Reader) (Login, error)
	Encode(w io.Writer, s Login) error
}

type Auth struct {
	LoginCodec     LoginCodec
	UserCodec      campid.UserCodec
	NewUserCodec   campid.NewUserCodec
	PhoneValidator campid.PhoneValidator
	EmailValidator campid.EmailValidator
	Passwords      *campid.Password
	Users          *campid.UserStore
	Zones          *campid.UserZoneManager
}

func (em *Auth) Register(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var newUser, decodeErr = em.NewUserCodec.Decode(bytes.NewReader(msg.Bytes))
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var user, err = em.RegisterUser(ctx, newUser)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	var userObjectForPublic = user.PublicSafeUser()
	var encodedUserDataWriter = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&encodedUserDataWriter)
	encodedUserDataWriter.Reset()

	if encodedErr := em.UserCodec.Encode(encodedUserDataWriter, &userObjectForPublic); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var encodedDataBytes = make([]byte, encodedUserDataWriter.Len())
	_ = copy(encodedDataBytes, encodedUserDataWriter.Bytes()[:encodedUserDataWriter.Len()])

	var newCraftedReply = msg.ReplyTo()
	newCraftedReply.Bytes = encodedDataBytes


	return tr.
}

func (em *Auth) RegisterUser(
	ctx context.Context,
	newUser campid.NewUser,
) (*campid.User, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var validateErr = newUser.Validate()
	if validateErr != nil {
		return nil, nerror.WrapOnly(validateErr.Err())
	}

	if len(newUser.Email) != 0 {
		if validateEmailErr := em.EmailValidator.Validate(newUser.Email); validateEmailErr != nil {
			return nil, nerror.WrapOnly(validateEmailErr)
		}
	}

	if len(newUser.Phone) != 0 {
		if validatePhoneErr := em.PhoneValidator.Validate(newUser.Phone); validatePhoneErr != nil {
			return nil, nerror.WrapOnly(validatePhoneErr)
		}
	}

	var hasUser bool
	var hasUserErr error
	if len(newUser.Email) != 0 && len(newUser.Phone) == 0 {
		hasUser, hasUserErr = em.Users.HasEmail(ctx, newUser.Phone)
	}

	if len(newUser.Email) == 0 && len(newUser.Phone) != 0 {
		hasUser, hasUserErr = em.Users.HasPhone(ctx, newUser.Phone)
	}

	if hasUserErr != nil {
		return nil, nerror.WrapOnly(hasUserErr)
	}

	if hasUser {
		return nil, nerror.WrapOnly(&campid.ExistingUserErr{})
	}

	var hashedPassword, hashedPasswordErr = em.Passwords.Hash(newUser.Password)
	if hashedPasswordErr != nil {
		return nil, nerror.WrapOnly(hashedPasswordErr)
	}

	var userData = newUser.ToUser()
	userData.HashedPassword = nunsafe.Bytes2String(hashedPassword)

	var createdUser, failedCreateUserErr = em.Users.Create(ctx, userData)
	if failedCreateUserErr != nil {
		return nil, nerror.WrapOnly(failedCreateUserErr)
	}

	var sessionData = map[string]string{}
	sessionData["email"] = createdUser.Email

	var _, createZoneErr = em.Zones.CreateZone(ctx, createdUser.Id, "api", sessionData)
	if createZoneErr != nil {
		return nil, nerror.WrapOnly(createZoneErr)
	}

	return createdUser, nil
}

func (em *Auth) Login(
	ctx context.Context,
	msg *sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login, decodeErr = em.LoginCodec.Decode(bytes.NewReader(msg.Bytes))
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var user, err = em.LoginUser(ctx, login)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	_ = user
	return nil
}

type LoggedInUser struct {
	User *campid.User
	Zone *campid.Zone
	Jwt  *campid.Claim
}

func (em *Auth) LoginUser(
	ctx context.Context,
	login Login,
) (*LoggedInUser, error) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := login.Validate(); validateErr != nil {
		return nil, nerror.WrapOnly(validateErr)
	}

	if len(login.Email) != 0 {
		if validateEmailErr := em.EmailValidator.Validate(login.Email); validateEmailErr != nil {
			return nil, nerror.WrapOnly(validateEmailErr)
		}
	}

	if len(login.Phone) != 0 {
		if validatePhoneErr := em.PhoneValidator.Validate(login.Phone); validatePhoneErr != nil {
			return nil, nerror.WrapOnly(validatePhoneErr)
		}
	}

	var retrievedErr error
	var retrievedUser *campid.User

	if login.IsPhone {
		retrievedUser, retrievedErr = em.Users.ByPhone(ctx, login.Phone)
	} else {
		retrievedUser, retrievedErr = em.Users.ByEmail(ctx, login.Email)
	}

	if retrievedErr != nil {
		return nil, nerror.Wrap(retrievedErr, "User not found by email or phone")
	}

	if passwordValidErr := em.Passwords.Validate(retrievedUser, login.Password); passwordValidErr != nil {
		return nil, nerror.Wrap(passwordValidErr, "Invalid user password")
	}

	var userZone, getZoneErr = em.Zones.Get(ctx, retrievedUser.Id)
	if getZoneErr != nil {
		return nil, nerror.WrapOnly(getZoneErr)
	}

	var jwtData = map[string]string{
		"user_id": retrievedUser.Id,
	}

	var _, claim, jwtErr = em.Zones.AddJwtSessionToZone(ctx, userZone.Id, userZone.UserId, jwtData)
	if jwtErr != nil {
		return nil, nerror.Wrap(jwtErr, "Failed to create jwt for user login")
	}

	return &LoggedInUser{
		User: retrievedUser,
		Zone: userZone,
		Jwt:  claim,
	}, nil
}

func (em *Auth) Refresh(
	ctx context.Context,
	msg *sabuhp.Message,
) ([]*sabuhp.Message, error) {
	return nil, nil
}

type RefreshLogin struct {
	UserId       string
	RefreshToken string
}

func (el RefreshLogin) Validate() error {
	if len(el.UserId) == 0 {
		return nerror.New("RefreshLogin.UserId is required")
	}
	if len(el.RefreshToken) == 0 {
		return nerror.New("RefreshLogin.RefreshToken is required")
	}
	return nil
}

type RefreshLoginCodec interface {
	Decode(r io.Reader) (RefreshLogin, error)
	Encode(w io.Writer, s RefreshLogin) error
}

func (em *Auth) RefreshLogin(
	ctx context.Context,
	msg *sabuhp.Message,
) ([]*sabuhp.Message, error) {
	return nil, nil
}

func (em *Auth) Callback(
	ctx context.Context,
	msg *sabuhp.Message,
) ([]*sabuhp.Message, error) {
	return nil, nil
}

func (em *Auth) Logout(
	ctx context.Context,
	msg *sabuhp.Message,
) ([]*sabuhp.Message, error) {
	return nil, nil
}
