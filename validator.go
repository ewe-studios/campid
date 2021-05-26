package campid

import (
	"regexp"

	"github.com/influx6/npkg/nerror"
)

var (
	emailRegexp = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

type EmailValidatorImpl struct{}

func (EmailValidatorImpl) Validate(email string) error {
	if !emailRegexp.MatchString(email) {
		return nerror.New("failed to validate email")
	}
	return nil
}
