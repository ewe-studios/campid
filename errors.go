package campid

type ExistingUserErr struct {}

func (e ExistingUserErr) Error() string {
	return "User already exists"
}
