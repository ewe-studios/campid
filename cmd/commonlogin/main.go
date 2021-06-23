package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ewe-studios/sabuhp/actions"
	"github.com/ewe-studios/sabuhp/servers/serviceServer"

	"github.com/dgrijalva/jwt-go"
	"github.com/influx6/npkg/nerror"

	"github.com/influx6/npkg/nenv"

	"github.com/blevesearch/bleve/v2"
	"github.com/influx6/npkg/nstorage/nredis"

	"github.com/ewe-studios/campid"
	"github.com/ewe-studios/campid/providers/commonLogin"

	"github.com/influx6/npkg/ndaemon"

	"github.com/ewe-studios/sabuhp"

	"github.com/ewe-studios/sabuhp/bus/redispub"
	"github.com/ewe-studios/sabuhp/servers/clientServer"
	redis "github.com/go-redis/redis/v8"
)

const (
	NAMESPACE         = "CAMPID"
	AddrENV           = "ADDR"
	ENV               = "ENV"
	GRP               = "GROUP"
	OWNER             = "OWNER"
	JwtEncKey         = "JWT_ENC_KEY"
	TwilioAccountSide = "TWILIO_ACCOUNT_SID"
	TwilioAuthToken   = "TWILIO_AUTH_TOKEN"
	TwilioPhoneNumber = "TWILIO_PHONE_NUMBER"
	SendGridAuth      = "SENDGRID_AUTH"
	SenderEmail       = "SenderEmail"
)

func main() {
	var envs = nenv.New(NAMESPACE)
	var loader nenv.EnvironmentLoader
	if err := loader.Register(envs); err != nil {
		log.Fatalf("Failed to load environment variables: %q\n", err)
	}

	log.Println("-> Loaded environment variables")

	if !envs.Has(JwtEncKey) {
		log.Fatalf("Failed to find environment variable: %q\n", envs.KeyFor(JwtEncKey))
	}

	var serviceOwner, hasServiceOwner = envs.GetString(OWNER)
	if !hasServiceOwner {
		log.Fatalf("%q is required", envs.KeyFor(OWNER))
	}

	var serviceEnv, hasServiceEnv = envs.GetString(ENV)
	if !hasServiceEnv {
		log.Fatalf("%q is required", envs.KeyFor(ENV))
	}

	var jwtPassword, hasJwtPassword = envs.GetString(JwtEncKey)
	if !hasJwtPassword {
		log.Fatalf("%q is required", envs.KeyFor(JwtEncKey))
	}

	var serviceAddr, hasServiceAddr = envs.GetString(AddrENV)
	if !hasServiceAddr {
		log.Fatalf("%q is required", envs.KeyFor(AddrENV))
	}

	var serviceGroup, hasServiceGroup = envs.GetString(GRP)
	if !hasServiceGroup {
		log.Fatalf("%q is required", envs.KeyFor(GRP))
	}

	var senderEmail, hasSenderEmail = envs.GetString(SenderEmail)
	if !hasSenderEmail {
		log.Fatalf("%q is required", envs.KeyFor(SenderEmail))
	}

	var sendGridAuth, hasSendGridAuth = envs.GetString(SendGridAuth)
	if !hasSendGridAuth {
		log.Fatalf("%q is required", envs.KeyFor(SendGridAuth))
	}

	var twilioEmailAuth, hasTwilioEmailAuth = envs.GetString(TwilioAuthToken)
	if !hasTwilioEmailAuth {
		log.Fatalf("%q is required", envs.KeyFor(TwilioAuthToken))
	}

	var twilioAccountSide, hasTwilioAccountSid = envs.GetString(TwilioAccountSide)
	if !hasTwilioAccountSid {
		log.Fatalf("%q is required", envs.KeyFor(TwilioAccountSide))
	}

	var twilioPhoneNumber, hasTwilioPhoneNumber = envs.GetString(TwilioPhoneNumber)
	if !hasTwilioPhoneNumber {
		log.Fatalf("%q is required", envs.KeyFor(TwilioPhoneNumber))
	}

	var topicMaker = sabuhp.CreateTopicPartial(serviceEnv, serviceOwner)

	var ctx, canceler = context.WithCancel(context.Background())
	ndaemon.WaiterForKillWithSignal(ndaemon.WaitForKillChan(), canceler)

	defer canceler()

	var logger sabuhp.GoLogImpl

	var redisConnect redis.Options
	var redisConfig = redispub.Config{
		Logger: logger,
		Ctx:    ctx,
		Redis:  redisConnect,
		Codec:  clientServer.DefaultCodec,
	}
	var redisBus, busErr = redispub.Stream(redisConfig)
	if busErr != nil {
		log.Fatalf("Failed to create bus connection: %q\n", busErr.Error())
	}

	redisBus.Start()

	var indexMapping, indexMappingErr = campid.CreateIndexMappingForAll()
	if indexMappingErr != nil {
		log.Fatalf("Failed to create bus connection: %q\n", indexMappingErr.Error())
	}

	var indexer, indexerErr = bleve.New("campid.commonLogin.index", indexMapping)
	if indexerErr != nil {
		log.Fatalf("Failed to create bus connection: %q\n", indexerErr.Error())
	}

	log.Println("-> Created index mapping and store")

	var redisStore, redisErr = nredis.NewRedisStore(ctx, "campid.commonLogin.db", redisConnect)
	if redisErr != nil {
		log.Fatalf("Failed to create bus connection: %q\n", redisErr.Error())
	}

	log.Println("-> Created index redis store")

	var codec campid.JsonCodec
	var deviceCodec campid.JsonDeviceCodec
	var userCodec = &campid.JsonUserCodec{Codec: codec}

	var deviceStore = campid.NewDeviceStore(&deviceCodec, redisStore, indexer)
	var jwtStore = campid.NewJWTStore(campid.JWTConfig{
		Issuer:     "CampId",
		Authorizer: "CampIdAPI",
		GetNewClaim: func() (jwt.MapClaims, jwt.SigningMethod, interface{}) {
			return jwt.MapClaims{}, jwt.SigningMethodHS256, jwtPassword
		},
		GetSigningKey: func(t *jwt.Token) (key interface{}, err error) {
			if _, isHMAC := t.Method.(*jwt.SigningMethodHMAC); !isHMAC {
				return nil, nerror.New("invalid signing method %q", t.Method.Alg())
			}
			return jwtPassword, nil
		},
		AccessTokenExpiration:  time.Minute,
		RefreshTokenExpiration: time.Minute * 6,
		GetTime:                time.Now,
		MapCodec:               &campid.JsonMapCodec{},
		Store:                  redisStore,
	})
	var zoneStore = campid.NewZoneStore(&campid.JsonZoneCodec{Codec: codec}, redisStore)

	var phoneValidator = new(campid.PhoneValidatorImpl)
	var emailValidator = new(campid.EmailValidatorImpl)

	var passwordManager = &campid.Password{
		Cost:      10,
		MinLength: 10,
		MaxLength: 70,
	}

	var smsTemplate = campid.NewSMSTemplateImpl("CampId Auth Code", "www.campid.io")
	var twilioPhoneCode = campid.NewTwilioTel(logger, smsTemplate, twilioAccountSide, twilioEmailAuth, twilioPhoneNumber)

	var emailTemplate = campid.NewEmailTemplateImpl("CampId Auth Code", "CampId Auth", "www.campid.io")
	var sendGridEmailCode = campid.NewTwilioEmailCode(logger, emailTemplate, sendGridAuth, senderEmail, "Campid Auth")

	var userStore = campid.NewUserStore(redisStore, userCodec, indexer, passwordManager, emailValidator, phoneValidator)
	var zoneManager = campid.NewZoneManager(zoneStore, jwtStore, deviceStore)
	var registrationCodes = campid.NewAuthCodes(twilioPhoneCode, sendGridEmailCode, 5*time.Minute, redisStore)

	var loginCodes = campid.NewDeviceAuthCodes(twilioPhoneCode, sendGridEmailCode, 5*time.Minute, redisStore)

	var auth commonLogin.Auth
	auth.Codec = &codec

	auth.Users = userStore
	auth.Topics = topicMaker
	auth.Zones = zoneManager

	auth.Passwords = passwordManager
	auth.PhoneValidator = phoneValidator
	auth.EmailValidator = emailValidator

	auth.LoginCodes = loginCodes
	auth.RegistrationCodes = registrationCodes

	var workers = actions.NewWorkerTemplateRegistry()
	var cs = serviceServer.New(
		ctx,
		logger,
		redisBus,
		serviceServer.WithWorkerRegistry(workers),
	)

	log.Println("-> Registering listeners")

	// register auth service with bus relay.
	auth.RegisterWithBusRelay(cs.BusRelay, serviceGroup)

	fmt.Println("-> Starting service")
	cs.Start()

	fmt.Printf("-> Started service on %q\n", serviceAddr)
	if err := cs.ErrGroup.Wait(); err != nil {
		log.Fatalf("service group finished with error: %s", err.Error())
	}

	fmt.Println("-> Closed worker service")
}
