package commonLogin

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"

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

type Auth struct {
	Codec          campid.Codec
	PhoneValidator campid.PhoneValidator
	EmailValidator campid.EmailValidator
	Passwords      *campid.Password
	Users          *campid.UserStore
	Zones          *campid.UserZoneManager
}

type RegisteredUser struct {
	User      campid.User
	When      time.Time
	FromTopic string
}

func (em *Auth) Register(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var newUser campid.NewUser
	var decodeErr = em.Codec.Decode(bytes.NewReader(msg.Bytes), &newUser)
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

	var registeredUser RegisteredUser
	registeredUser.User = userObjectForPublic
	registeredUser.FromTopic = msg.Topic
	registeredUser.When = time.Now()

	if encodedErr := em.Codec.Encode(encodedUserDataWriter, registeredUser); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var newCraftedReply = msg.ReplyWithTopic(campid.RegisteredUserTopic)
	newCraftedReply.Bytes = campid.CopyBufferBytes(encodedUserDataWriter)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)
	return nil
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
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login Login
	var decodeErr = em.Codec.Decode(bytes.NewReader(msg.Bytes), &login)
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var user, err = em.LoginUser(ctx, login)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := em.Codec.Encode(buffer, &user); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var newCraftedReply = msg.ReplyWithTopic(campid.LoggedInUserTopic)
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)
	return nil
}

type LoggedInUser struct {
	ZoneId         string
	AccessToken    string
	RefreshToken   string
	RefreshExpires int64
	AccessExpires  int64
	User           campid.User
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
		User:           retrievedUser.PublicSafeUser(),
		ZoneId:         userZone.Id,
		RefreshToken:   claim.RefreshToken,
		AccessToken:    claim.AccessToken,
		RefreshExpires: claim.RefreshExpires,
		AccessExpires:  claim.AccessExpires,
	}, nil
}

type RefreshUserAccess struct {
	RefreshToken string `json:"refresh_token"`
}

func (el RefreshUserAccess) Validate() error {
	if len(el.RefreshToken) == 0 {
		return nerror.New("RefreshLogin.RefreshToken is required")
	}
	return nil
}

func (em *Auth) Refresh(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login RefreshUserAccess
	var decodeErr = em.Codec.Decode(bytes.NewReader(msg.Bytes), &login)
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var refreshedDetail, err = em.RefreshLogin(ctx, login)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := em.Codec.Encode(buffer, &refreshedDetail); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var newCraftedReply = msg.ReplyWithTopic(campid.RefreshedUserTopic)
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

type RefreshedLogin struct {
	UserId         string
	ZoneId         string
	AccessToken    string
	RefreshToken   string
	RefreshExpires int64
	AccessExpires  int64
}

func (em *Auth) RefreshLogin(
	ctx context.Context,
	req RefreshUserAccess,
) (RefreshedLogin, error) {
	var refreshed RefreshedLogin

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := req.Validate(); validateErr != nil {
		return refreshed, nerror.WrapOnly(validateErr)
	}

	var claim, claimErr = em.Zones.JwtStore.Refresh(ctx, req.RefreshToken)
	if claimErr != nil {
		return refreshed, nerror.WrapOnly(claimErr)
	}

	refreshed.UserId = claim.UserId
	refreshed.AccessToken = claim.AccessToken
	refreshed.RefreshToken = claim.RefreshToken
	refreshed.AccessExpires = claim.AccessExpires
	refreshed.RefreshExpires = claim.RefreshExpires

	return refreshed, nil
}

type VerifyAccess struct {
	AccessToken string
}

func (v VerifyAccess) Validate() error {
	if len(v.AccessToken) == 0 {
		return nerror.New("VerifiedAccess.AccessToken is required")
	}
	return nil
}

func (em *Auth) Verify(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login VerifyAccess
	var decodeErr = em.Codec.Decode(bytes.NewReader(msg.Bytes), &login)
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var refreshedDetail, err = em.VerifyAccess(ctx, login)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := em.Codec.Encode(buffer, &refreshedDetail); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var newCraftedReply = msg.ReplyWithTopic(campid.VerifiedUserTopic)
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

type VerifiedAccess struct {
	UserId string
	ZoneId string
}

func (em *Auth) VerifyAccess(
	ctx context.Context,
	ve VerifyAccess,
) (VerifiedAccess, error) {
	var vs VerifiedAccess

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := ve.Validate(); validateErr != nil {
		return vs, nerror.WrapOnly(validateErr)
	}

	var claim, _, claimErr = em.Zones.JwtStore.VerifyAccess(ctx, ve.AccessToken)
	if claimErr != nil {
		return vs, nerror.WrapOnly(claimErr)
	}

	vs.UserId = claim.UserId
	vs.ZoneId = claim.ZoneId

	return vs, nil
}

func (em *Auth) FinishAuth(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var newCraftedReply = msg.ReplyWithTopic(campid.FinishAuthUserTopic)
	newCraftedReply.Bytes = []byte(campid.NOT_SUPPORTED)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)
	return nil
}

type LogoutUser struct {
	AccessToken string
}

func (l LogoutUser) Validate() error {
	if len(l.AccessToken) == 0 {
		return nerror.New("LogoutUser.AccessToken is required")
	}
	return nil
}

func (em *Auth) Logout(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var lg LogoutUser
	var decodeErr = em.Codec.Decode(bytes.NewReader(msg.Bytes), &lg)
	if decodeErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(decodeErr), false)
	}

	var response, err = em.LogoutUser(ctx, lg)
	if err != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(err), false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := em.Codec.Encode(buffer, &response); encodedErr != nil {
		return sabuhp.WrapErr(nerror.WrapOnly(encodedErr), false)
	}

	var newCraftedReply = msg.ReplyWithTopic(campid.LoggedOutUserTopic)
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	return nil
}

type LoggedOutUser struct {
	UserId string
}

func (em *Auth) LogoutUser(
	ctx context.Context,
	lg LogoutUser,
) (LoggedOutUser, error) {
	var lo LoggedOutUser

	var claim, _, err = em.Zones.JwtStore.AccessTokenToClaim(ctx, lg.AccessToken)
	if err != nil {
		return lo, nerror.Wrap(err, "failed to find access token claim")
	}

	// delete refresh token
	var _, removeRefreshTokenErr = em.Zones.JwtStore.RemoveRefreshId(ctx, claim.RefreshId.String())
	if removeRefreshTokenErr != nil {
		return lo, nerror.Wrap(removeRefreshTokenErr, "failed to find remove access id refresh token")
	}

	// delete related access id
	var userId, removeAccessErr = em.Zones.JwtStore.RemoveAccessId(ctx, claim.AccessId.String())
	if removeAccessErr != nil {
		return lo, nerror.Wrap(removeAccessErr, "failed to find remove access id")
	}

	lo.UserId = userId

	return lo, nil
}
