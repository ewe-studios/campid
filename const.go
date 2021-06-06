package campid

const (
	NOT_SUPPORTED = "NOT SUPPORTED"
)

// Auth manager events
const (
	LogOutUserTopic           = "campid.users.logOutUser"
	LoggedOutUserTopic        = "campid.users.loggedOutUser"
	LogInUserTopic            = "campid.users.logInUser"
	LoggedInUserTopic         = "campid.users.loggedInUser"
	RefreshUserTopic          = "campid.users.refreshUser"
	RefreshedUserTopic        = "campid.users.refreshedUser"
	VerifyUserTopic           = "campid.users.verifyUser"
	VerifiedUserTopic         = "campid.users.verifiedUser"
	RegisterUserTopic         = "campid.users.registerUser"
	RegisteredUserTopic       = "campid.users.registeredUser"
	FinishLoginUserTopic      = "campid.users.finishUserAuth"
	FinishedLoginUserTopic    = "campid.users.finishedUserAuth"
	FinishRegistrationTopic   = "campid.users.finishRegistration"
	FinishedRegistrationTopic = "campid.users.finishedRegistration"
)

// Jwt service events
const (
	AddedJwtTopic     = "campid.jwt.deletedJwt"
	DisabledJwtTopic  = "campid.jwt.disabledJwt"
	DeletedJwtTopic   = "campid.jwt.deletedJwt"
	ExpiredJwtTopic   = "campid.jwt.expiredJwt"
	RefreshedJwtTopic = "campid.jwt.refreshedJwt"
)

// Device service events
const (
	CreateDeviceTopic           = "campid.devices.createDevice"
	DeviceCreatedTopic          = "campid.devices.deviceCreated"
	RemoveDeviceTopic           = "campid.devices.removeDevice"
	DeviceRemovedTopic          = "campid.devices.removedDevice"
	RemoveDevicesForZoneTopic   = "campid.devices.removeDevice"
	DevicesRemovedTopic         = "campid.devices.removedDevices"
	EnableDeviceTopic           = "campid.devices.deviceEnabled"
	DeviceEnabledTopic          = "campid.devices.deviceEnabled"
	DisableDeviceTopic          = "campid.devices.deviceEnabled"
	DeviceDisabledTopic         = "campid.devices.deviceEnabled"
	UpdateDeviceTopic           = "campid.devices.updateDevice"
	DeviceUpdatedTopic          = "campid.devices.deviceUpdated"
	GetAllDevicesTopic          = "campid.devices.getAllDevices"
	GetDeviceTopic              = "campid.devices.getDevice"
	GetDevicesForZoneTopic      = "campid.devices.getDevicesForZone"
	GetDevicesForCityTopic      = "campid.devices.getDevicesForCity"
	GetDevicesForUserTopic      = "campid.devices.getDevicesForUser"
	GetDevicesForCityAndIpTopic = "campid.devices.getDevicesForCityAndIp"
)

// Action service events
const (
	CreateActionTopic  = "campid.actions.createAction"
	ActionCreatedTopic = "campid.actions.createdAction"
	DeleteActionTopic  = "campid.actions.deleteAction"
	ActionDeletedTopic = "campid.actions.deletedAction"
)

// Role service events
const (
	CreateRoleTopic            = "campid.roles.createRole"
	RoleCreatedTopic           = "campid.roles.createdRole"
	DeleteRoleTopic            = "campid.roles.deleteRole"
	RoleDeletedTopic           = "campid.roles.deletedRole"
	UpdateRoleTopic            = "campid.roles.updateRole"
	RoleUpdatedTopic           = "campid.roles.updatedRole"
	GetRoleTopic               = "campid.roles.getRole"
	GetAllRolesTopic           = "campid.roles.getAllRoles"
	GetRoleWithActionTopic     = "campid.roles.getRoleWithAction"
	GetRolesWithActionsTopic   = "campid.roles.getRolesWithAction"
	GetRolesWithAnyActionTopic = "campid.roles.getRolesWithAnyAction"
)

// Group service events
const (
	CreateGroupTopic            = "campid.groups.createGroup"
	GroupCreatedTopic           = "campid.groups.createdGroup"
	DeleteGroupTopic            = "campid.groups.deleteGroup"
	GroupDeletedTopic           = "campid.groups.deletedGroup"
	UpdateGroupTopic            = "campid.groups.updateGroup"
	GroupUpdatedTopic           = "campid.groups.updatedGroup"
	GetAllGroupsTopic           = "campid.groups.getAllGroups"
	GetGroupTopic               = "campid.groups.getGroup"
	GetGroupWithRoleTopic       = "campid.groups.getGroupWithRole"
	GetGroupWithRolesTopic      = "campid.groups.getGroupWithRoles"
	GetGroupWithAnyOfRolesTopic = "campid.groups.getGroupWithAnyOfRoles"
)

// Zone service events
const (
	CreateZoneTopic  = "campid.zone.createZone"
	ZoneCreatedTopic = "campid.zone.createdZone"
	UpdateZoneTopic  = "campid.zone.updateZone"
	ZoneUpdatedTopic = "campid.zone.updatedZone"
	DeleteZoneTopic  = "campid.zone.deleteZone"
	ZoneDeletedTopic = "campid.zone.deletedZone"
)

// User service events
const (
	CreateUserTopic  = "campid.users.createUser"
	UserCreatedTopic = "campid.users.createdUser"
	UpdateUserTopic  = "campid.users.updateUser"
	UserUpdatedTopic = "campid.users.updatedUser"
	DeleteUserTopic  = "campid.users.deleteUser"
	DeletedUserTopic = "campid.users.deletedUser"
)
