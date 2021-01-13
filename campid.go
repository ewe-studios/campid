package campid

type EmailLogin struct {
	Email    string
	Password string
}

type UsernameLogin struct {
	Username string
	Password string
}

type Mailer interface {
	SendMail() error
}

type Telephone interface {
	SendText() error
}
