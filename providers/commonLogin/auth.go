package commonLogin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ewe-studios/campid"
	"github.com/ewe-studios/sabuhp"
	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/ntrace"
	openTracing "github.com/opentracing/opentracing-go"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

var _ campid.Authenticator = (*Auth)(nil)

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
	Topics         sabuhp.TopicPartial
}

type RegisteredUser struct {
	User      campid.User
	When      time.Time
	FromTopic string
	Error     error
}

func (auth *Auth) RegisterWithBusRelay(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(campid.LogOutUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Logout))
	bus.Group(campid.LogInUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Login))
	bus.Group(campid.RefreshUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.RefreshAccess))
	bus.Group(campid.VerifyUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.VerifyAccess))
	bus.Group(campid.RegisterUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Register))
	bus.Group(campid.FinishLoginUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.FinishLogin))
	bus.Group(campid.FinishRegistrationTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.FinishRegistration))
}

func (auth *Auth) Register(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var newUser campid.NewUser
	var decodeErr = auth.Codec.Decode(bytes.NewReader(msg.Bytes), &newUser)
	if decodeErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodeErr), http.StatusBadRequest, true)
	}

	var user, err = auth.RegisterUser(ctx, newUser)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), true)
	}

	var userObjectForPublic = user.PublicSafeUser()
	var encodedUserDataWriter = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&encodedUserDataWriter)
	encodedUserDataWriter.Reset()

	var registeredUser RegisteredUser
	registeredUser.User = userObjectForPublic
	registeredUser.FromTopic = msg.Topic.String()
	registeredUser.When = time.Now()

	if encodedErr := auth.Codec.Encode(encodedUserDataWriter, registeredUser); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.RegisteredUserTopic))
	newCraftedReply.Bytes = campid.CopyBufferBytes(encodedUserDataWriter)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)
	return nil
}

func (auth *Auth) RegisterUser(
	ctx context.Context,
	newUser campid.NewUser,
) (*campid.User, sabuhp.MessageErr) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var createdUser, failedCreateUserErr = auth.Users.Register(ctx, newUser)
	if failedCreateUserErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(failedCreateUserErr), http.StatusInternalServerError, false)
	}

	var sessionData = map[string]string{}
	sessionData["email"] = createdUser.Email

	var _, createZoneErr = auth.Zones.CreateZone(ctx, createdUser.Id, "api", sessionData)
	if createZoneErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(createZoneErr), http.StatusInternalServerError, false)
	}

	return createdUser, nil
}

func (auth *Auth) Login(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login Login
	var decodeErr = auth.Codec.Decode(bytes.NewReader(msg.Bytes), &login)
	if decodeErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodeErr), http.StatusBadRequest, false)
	}

	var user, err = auth.LoginUser(ctx, login)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), false)
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := auth.Codec.Encode(buffer, &user); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var data = campid.CopyBufferBytes(buffer)

	// send to event for logged in user
	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.LoggedInUserTopic))
	newCraftedReply.Headers.Add("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))
	newCraftedReply.Cookies = append(newCraftedReply.Cookies, sabuhp.Cookie{Name: "accessToken", Value: user.AccessToken, HttpOnly: true})
	newCraftedReply.Cookies = append(newCraftedReply.Cookies, sabuhp.Cookie{Name: "refreshToken", Value: user.RefreshToken, HttpOnly: true})
	newCraftedReply.Bytes = data
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
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

func (auth *Auth) LoginUser(
	ctx context.Context,
	login Login,
) (*LoggedInUser, sabuhp.MessageErr) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := login.Validate(); validateErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(validateErr), http.StatusBadRequest, true)
	}

	var retrievedErr error
	var retrievedUser *campid.User

	if login.IsPhone {
		retrievedUser, retrievedErr = auth.Users.ByPhone(ctx, login.Phone)
	} else {
		retrievedUser, retrievedErr = auth.Users.ByEmail(ctx, login.Email)
	}

	if retrievedErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.Wrap(retrievedErr, "User not found by email or phone"), http.StatusBadRequest, true)
	}

	if passwordValidErr := auth.Passwords.Validate(retrievedUser, login.Password); passwordValidErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.Wrap(passwordValidErr, "Invalid user password"), http.StatusBadRequest, true)
	}

	var userZone, getZoneErr = auth.Zones.Get(ctx, retrievedUser.Id)
	if getZoneErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getZoneErr), http.StatusInternalServerError, true)
	}

	var jwtData = map[string]string{
		"user_id": retrievedUser.Id,
	}

	var _, claim, jwtErr = auth.Zones.AddJwtSessionToZone(ctx, userZone.Id, userZone.UserId, jwtData)
	if jwtErr != nil {
		return nil, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(jwtErr), http.StatusInternalServerError, true)
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

func (auth *Auth) FinishLogin(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedLoginUserTopic))
	newCraftedReply.Bytes = []byte(campid.NOT_SUPPORTED)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

func (auth *Auth) VerifyLogin(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedRegistrationTopic))
	newCraftedReply.Bytes = []byte(campid.NOT_SUPPORTED)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

type RefreshUserAccess struct {
	RefreshToken string `json:"refresh_token"`
}

func (el RefreshUserAccess) Validate() error {
	if len(el.RefreshToken) == 0 {
		return nerror.New("RefreshUserAccess.RefreshToken is required")
	}
	return nil
}

func (auth *Auth) RefreshAccess(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login RefreshUserAccess
	login.RefreshToken = msg.Params.Get("refreshToken")

	if len(login.RefreshToken) == 0 {
		for _, cookie := range msg.Cookies {
			if cookie.Name == "refreshToken" {
				login.RefreshToken = cookie.Value
				break
			}
		}
	}

	var refreshedDetail, err = auth.RefreshUserAccess(ctx, login)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), err.ShouldAck())
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := auth.Codec.Encode(buffer, &refreshedDetail); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.RefreshedUserTopic))
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
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

func (auth *Auth) RefreshUserAccess(
	ctx context.Context,
	req RefreshUserAccess,
) (RefreshedLogin, sabuhp.MessageErr) {
	var refreshed RefreshedLogin

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := req.Validate(); validateErr != nil {
		return refreshed, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(validateErr), http.StatusBadRequest, true)
	}

	var claim, claimErr = auth.Zones.JwtStore.Refresh(ctx, req.RefreshToken)
	if claimErr != nil {
		return refreshed, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(claimErr), http.StatusBadRequest, true)
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

func (auth *Auth) VerifyAccess(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var login VerifyAccess

	var authorizationHeader = strings.TrimPrefix(msg.Headers.Get("Authorization"), "Bearer")
	login.AccessToken = strings.TrimSpace(authorizationHeader)

	if len(login.AccessToken) == 0 {
		login.AccessToken = msg.Params.Get("accessToken")
	}

	if len(login.AccessToken) == 0 {
		for _, cookie := range msg.Cookies {
			if cookie.Name == "accessToken" {
				login.AccessToken = cookie.Value
				break
			}
		}
	}

	var refreshedDetail, err = auth.VerifyUserAccess(ctx, login)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), err.ShouldAck())
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := auth.Codec.Encode(buffer, &refreshedDetail); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.VerifiedUserTopic))
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

type VerifiedAccess struct {
	UserId string
	ZoneId string
}

func (auth *Auth) VerifyUserAccess(
	ctx context.Context,
	ve VerifyAccess,
) (VerifiedAccess, sabuhp.MessageErr) {
	var vs VerifiedAccess

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := ve.Validate(); validateErr != nil {
		return vs, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(validateErr), http.StatusBadRequest, true)
	}

	var claim, _, claimErr = auth.Zones.JwtStore.VerifyAccess(ctx, ve.AccessToken)
	if claimErr != nil {
		return vs, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(claimErr), http.StatusBadRequest, true)
	}

	vs.UserId = claim.UserId
	vs.ZoneId = claim.ZoneId

	return vs, nil
}

func (auth *Auth) VerifyRegistration(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedRegistrationTopic))
	newCraftedReply.Bytes = []byte(campid.NOT_SUPPORTED)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

func (auth *Auth) FinishRegistration(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedRegistrationTopic))
	newCraftedReply.Bytes = []byte(campid.NOT_SUPPORTED)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
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

func (auth *Auth) Logout(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var lg LogoutUser
	lg.AccessToken = msg.Params.Get("accessToken")

	var response, err = auth.LogoutUser(ctx, lg)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), err.ShouldAck())
	}

	var buffer = bufferPool.New().(*bytes.Buffer)
	defer bufferPool.Put(&buffer)
	if encodedErr := auth.Codec.Encode(buffer, &response); encodedErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(encodedErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.LoggedOutUserTopic))
	newCraftedReply.Bytes = campid.CopyBufferBytes(buffer)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

type LoggedOutUser struct {
	UserId string
}

func (auth *Auth) LogoutUser(
	ctx context.Context,
	lg LogoutUser,
) (LoggedOutUser, sabuhp.MessageErr) {
	var lo LoggedOutUser

	var claim, _, err = auth.Zones.JwtStore.AccessTokenToClaim(ctx, lg.AccessToken)
	if err != nil {
		return lo, sabuhp.WrapErrWithStatusCode(nerror.Wrap(err, "failed to find access token claim"), http.StatusBadRequest, true)
	}

	// delete refresh token
	var _, removeRefreshTokenErr = auth.Zones.JwtStore.RemoveRefreshId(ctx, claim.RefreshId.String())
	if removeRefreshTokenErr != nil {
		return lo, sabuhp.WrapErrWithStatusCode(nerror.Wrap(removeRefreshTokenErr, "failed to find remove access id refresh token"), http.StatusBadRequest, true)
	}

	// delete related access id
	var userId, removeAccessErr = auth.Zones.JwtStore.RemoveAccessId(ctx, claim.AccessId.String())
	if removeAccessErr != nil {
		return lo, sabuhp.WrapErrWithStatusCode(nerror.Wrap(removeAccessErr, "failed to find remove access id"), http.StatusBadRequest, true)
	}

	lo.UserId = userId

	return lo, nil
}
