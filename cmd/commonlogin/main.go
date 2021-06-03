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
	NAMESPACE = "CAMPID"
	AddrENV   = "ADDR"
	ENV       = "ENV"
	GRP       = "GROUP"
	OWNER     = "OWNER"
	JwtEncKey = "JWT_ENC_KEY"
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

	var serviceEnv, _ = envs.GetString(ENV)
	var serviceOwner, _ = envs.GetString(OWNER)
	var jwtPassword, _ = envs.GetString(JwtEncKey)
	var serviceAddr, _ = envs.GetString(AddrENV)
	var serviceGroup, _ = envs.GetString(GRP)

	var LogOutUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.LogOutUserTopic)
	var LoggedOutUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.LoggedOutUserTopic)
	var LogInUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.LogInUserTopic)
	var LoggedInUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.LoggedInUserTopic)
	var RefreshUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.RefreshUserTopic)
	var RefreshedUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.RefreshedUserTopic)
	var VerifyUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.VerifyUserTopic)
	var VerifiedUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.VerifiedUserTopic)
	var RegisterUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.RegisterUserTopic)
	var RegisteredUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.RegisteredUserTopic)
	var FinishAuthUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.FinishAuthUserTopic)
	var FinishedAuthUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.FinishedAuthUserTopic)
	//var CreateUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.CreateUserTopic)
	var CreatedUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.CreatedUserTopic)
	//var DeleteUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.DeleteUserTopic)
	var DeletedUserTopic = sabuhp.TRS(serviceEnv, serviceOwner, campid.DeletedUserTopic)

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

	var auth commonLogin.Auth
	auth.Codec = &codec
	//auth.LogOutUserTopic = LogInUserTopic
	auth.LoggedOutUserTopic = LoggedOutUserTopic
	//auth.LogInUserTopic = LogInUserTopic
	auth.LoggedInUserTopic = LoggedInUserTopic
	//auth.RefreshUserTopic = RefreshUserTopic
	auth.RefreshedUserTopic = RefreshedUserTopic
	//auth.VerifyUserTopic = VerifyUserTopic
	auth.VerifiedUserTopic = VerifiedUserTopic
	//auth.RegisterUserTopic = RegisterUserTopic
	auth.RegisteredUserTopic = RegisteredUserTopic
	//auth.FinishAuthUserTopic = FinishAuthUserTopic
	auth.FinishedAuthUserTopic = FinishedAuthUserTopic
	//auth.CreateUserTopic = CreateUserTopic
	auth.CreatedUserTopic = CreatedUserTopic
	//auth.DeleteUserTopic = DeleteUserTopic
	auth.DeletedUserTopic = DeletedUserTopic

	auth.PhoneValidator = &campid.PhoneValidatorImpl{}
	auth.EmailValidator = &campid.EmailValidatorImpl{}
	auth.Passwords = &campid.Password{
		Cost:      10,
		MinLength: 10,
		MaxLength: 70,
	}
	auth.Users = campid.NewUserStore(redisStore, userCodec, indexer, auth.Passwords, auth.EmailValidator, auth.PhoneValidator)
	auth.Zones = campid.NewZoneManager(zoneStore, jwtStore, deviceStore)

	var workers = actions.NewWorkerTemplateRegistry()
	var cs = serviceServer.New(
		ctx,
		logger,
		redisBus,
		serviceServer.WithWorkerRegistry(workers),
	)

	log.Println("-> Registering listeners")

	// register auth service with bus relay.
	cs.BusRelay.Group(LogOutUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Logout))
	cs.BusRelay.Group(LogInUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Login))
	cs.BusRelay.Group(RefreshUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Refresh))
	cs.BusRelay.Group(VerifyUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Verify))
	cs.BusRelay.Group(RegisterUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.Register))
	cs.BusRelay.Group(FinishAuthUserTopic.String(), serviceGroup).Listen(sabuhp.TransportResponseFunc(auth.FinishAuth))

	fmt.Println("-> Starting service")
	cs.Start()

	fmt.Printf("-> Started service on %q\n", serviceAddr)
	if err := cs.ErrGroup.Wait(); err != nil {
		log.Fatalf("service group finished with error: %s", err.Error())
	}

	fmt.Println("-> Closed worker service")
}
