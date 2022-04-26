package commonLogin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
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

type Auth struct {
	Codec             campid.Codec
	PhoneValidator    campid.PhoneValidator
	EmailValidator    campid.EmailValidator
	RegistrationCodes *campid.AuthCodes
	LoginCodes        *campid.DeviceAuthCodes
	Devices           *campid.DeviceStore
	Passwords         *campid.Password
	Users             *campid.UserStore
	Zones             *campid.UserZoneManager
	Topics            sabuhp.TopicPartial
}

type RegisteredUser struct {
	User      campid.User
	When      time.Time
	FromTopic string
	Error     error
}

func (auth *Auth) RegisterWithBusRelay(bus *sabuhp.BusRelay, serviceGroup string) {
	bus.Group(campid.SendLoginVerificationTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.VerifyLogin))
	bus.Group(campid.LogOutUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Logout))
	bus.Group(campid.LogInUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Login))
	bus.Group(campid.RefreshUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.RefreshAccess))
	bus.Group(campid.VerifyUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.VerifyAccess))
	bus.Group(campid.RegisterUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Register))
	bus.Group(campid.FinishLoginUserTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.FinishLogin))
	bus.Group(campid.FinishRegistrationTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.FinishRegistration))
	bus.Group(campid.SendRegistrationVerificationTopic, serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.VerifyRegistration))
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

	var userObjectForPublic = user.User.PublicSafeUser()
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

type UserZone struct {
	User *campid.User
	Zone *campid.Zone
}

func (auth *Auth) RegisterUser(
	ctx context.Context,
	newUser campid.NewUser,
) (UserZone, sabuhp.MessageErr) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var uz UserZone

	var createdUser, failedCreateUserErr = auth.Users.Register(ctx, newUser)
	if failedCreateUserErr != nil {
		return uz, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(failedCreateUserErr), http.StatusInternalServerError, false)
	}

	var sessionData = map[string]string{}
	sessionData["email"] = createdUser.Email

	var zone, createZoneErr = auth.Zones.CreateZone(ctx, createdUser.Id, "api", sessionData)
	if createZoneErr != nil {
		return uz, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(createZoneErr), http.StatusInternalServerError, false)
	}

	sessionData["zoneId"] = zone.Id

	uz.User = createdUser
	uz.Zone = zone

	// send verification code for user
	if sendErr := auth.RegistrationCodes.SendCode(ctx, createdUser); sendErr != nil {
		return uz, sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(sendErr), http.StatusInternalServerError, false)
	}

	return uz, nil
}

func (auth *Auth) VerifyRegistration(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var userId = msg.Params.Get("userId")
	if len(userId) == 0 {
		return sabuhp.WrapErrWithStatusCode(nerror.New("userId is required"), http.StatusBadRequest, true)
	}
	var authCode = msg.Params.Get("regCode")
	if len(authCode) == 0 {
		return sabuhp.WrapErrWithStatusCode(nerror.New("regCode is required"), http.StatusBadRequest, true)
	}

	var currentUser, getUserErr = auth.Users.ById(ctx, userId)
	if getUserErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getUserErr), http.StatusInternalServerError, false)
	}

	var sendErr = auth.RegistrationCodes.VerifyCode(ctx, currentUser, authCode)
	if sendErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(sendErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.SentRegistrationVerificationTopic))
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
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var authenticationUser = msg.Params.Get("userId")
	if len(authenticationUser) == 0 {
		return sabuhp.WrapErrWithStatusCode(
			nerror.New("userId param is required"),
			http.StatusBadRequest,
			true,
		)
	}

	var user, getUserErr = auth.Users.ById(ctx, authenticationUser)
	if getUserErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getUserErr), http.StatusBadRequest, true)
	}

	var authenticationCode = msg.Params.Get("authCode")
	if len(authenticationCode) == 0 {
		return sabuhp.WrapErrWithStatusCode(
			nerror.New("authCode param is required"),
			http.StatusBadRequest,
			true,
		)
	}

	var authErr = auth.RegistrationCodes.VerifyCode(ctx, user, authenticationCode)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedRegistrationTopic))
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
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

func (auth *Auth) Login(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var deviceInfo, getDeviceInfoErr = campid.ExtractDeviceInfo(&msg)
	if getDeviceInfoErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceInfoErr), http.StatusBadRequest, true)
	}

	var device, getDeviceErr = auth.Devices.GetDeviceFromDeviceInfo(ctx, deviceInfo)
	if getDeviceErr != nil {
		device, getDeviceErr = auth.Devices.Create(ctx, deviceInfo)
		if getDeviceErr != nil {
			return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceErr), http.StatusBadRequest, true)
		}
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

	// send code to user's desired auth point
	if sendCodeErr := auth.LoginCodes.SendCode(ctx, &user.User, device); sendCodeErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(decodeErr), http.StatusBadRequest, false)
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

	var vauth, authErr = campid.ExtractJwtAuth(&msg)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var response, err = auth.LogoutUser(ctx, vauth)
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
	lg campid.VerifyAccess,
) (LoggedOutUser, sabuhp.MessageErr) {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

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

	var retrievedUser, retrieveErr = auth.Users.ById(ctx, userId)
	if retrieveErr != nil {
		return lo, sabuhp.WrapErrWithStatusCode(nerror.Wrap(retrieveErr, "failed to find user"), http.StatusInternalServerError, false)
	}

	var expireCodeErr = auth.LoginCodes.ExpireCode(ctx, retrievedUser)
	if expireCodeErr != nil {
		return lo, sabuhp.WrapErrWithStatusCode(nerror.Wrap(expireCodeErr, "failed to expire pending login code"), http.StatusInternalServerError, false)
	}

	lo.UserId = userId

	return lo, nil
}

func (auth *Auth) VerifyLogin(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var vauth, authErr = campid.ExtractJwtAuth(&msg)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var refreshedDetail, err = auth.VerifyUserAccess(ctx, vauth)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), err.ShouldAck())
	}

	var deviceInfo, getDeviceInfoErr = campid.ExtractDeviceInfo(&msg)
	if getDeviceInfoErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceInfoErr), http.StatusBadRequest, true)
	}

	var device, getDeviceErr = auth.Devices.GetDeviceFromDeviceInfo(ctx, deviceInfo)
	if getDeviceErr != nil {
		device, getDeviceErr = auth.Devices.Create(ctx, deviceInfo)
		if getDeviceErr != nil {
			return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceErr), http.StatusBadRequest, true)
		}
	}

	var currentUser, getUserErr = auth.Users.ById(ctx, refreshedDetail.UserId)
	if getUserErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getUserErr), http.StatusInternalServerError, false)
	}

	var sendErr = auth.LoginCodes.SendCode(ctx, currentUser, device)
	if sendErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(sendErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.SentLoginVerificationTopic))
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

func (auth *Auth) FinishLogin(
	ctx context.Context,
	msg sabuhp.Message,
	tr sabuhp.Transport,
) sabuhp.MessageErr {
	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	var authCode = msg.Params.Get("authCode")
	if len(authCode) == 0 {
		return sabuhp.WrapErrWithStatusCode(nerror.New("authCode is required"), http.StatusBadRequest, true)
	}

	var vauth, authErr = campid.ExtractJwtAuth(&msg)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var refreshedDetail, err = auth.VerifyUserAccess(ctx, vauth)
	if err != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(err), err.StatusCode(), err.ShouldAck())
	}

	var currentUser, getUserErr = auth.Users.ById(ctx, refreshedDetail.UserId)
	if getUserErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getUserErr), http.StatusInternalServerError, false)
	}

	var deviceInfo, getDeviceInfoErr = campid.ExtractDeviceInfo(&msg)
	if getDeviceInfoErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceInfoErr), http.StatusBadRequest, true)
	}

	var device, getDeviceErr = auth.Devices.GetDeviceFromDeviceInfo(ctx, deviceInfo)
	if getDeviceErr != nil {
		device, getDeviceErr = auth.Devices.Create(ctx, deviceInfo)
		if getDeviceErr != nil {
			return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(getDeviceErr), http.StatusBadRequest, true)
		}
	}

	var sendErr = auth.LoginCodes.VerifyCode(ctx, currentUser, device, authCode)
	if sendErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(sendErr), http.StatusInternalServerError, false)
	}

	var newCraftedReply = msg.ReplyWithTopic(auth.Topics(campid.FinishedLoginUserTopic))
	newCraftedReply.Bytes = []byte(campid.NotSupported)
	newCraftedReply.SuggestedStatusCode = http.StatusOK
	tr.ToBoth(newCraftedReply)

	// send to reply topic as well
	newCraftedReply.Topic = msg.Topic.ReplyTopic()
	tr.ToBoth(newCraftedReply)
	return nil
}

type VerifyAccess struct {
	AccessToken string
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

	var vauth, authErr = campid.ExtractJwtAuth(&msg)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var refreshedDetail, err = auth.VerifyUserAccess(ctx, vauth)
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
	ve campid.VerifyAccess,
) (VerifiedAccess, sabuhp.MessageErr) {
	var vs VerifiedAccess

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := ve.ValidateAccess(); validateErr != nil {
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

	var vauth, authErr = campid.ExtractJwtAuth(&msg)
	if authErr != nil {
		return sabuhp.WrapErrWithStatusCode(nerror.WrapOnly(authErr), http.StatusBadRequest, true)
	}

	var refreshedDetail, err = auth.RefreshUserAccess(ctx, vauth)
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
	req campid.VerifyAccess,
) (RefreshedLogin, sabuhp.MessageErr) {
	var refreshed RefreshedLogin

	var span openTracing.Span
	if ctx, span = ntrace.NewMethodSpanFromContext(ctx); span != nil {
		defer span.Finish()
	}

	if validateErr := req.ValidateRefresh(); validateErr != nil {
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
