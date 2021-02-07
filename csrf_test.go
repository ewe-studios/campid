package campid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSRFManager(t *testing.T) {
	var manager = NewCSRFManager("mykey")

	var crsfToken, createErr = manager.Create("1")
	require.NoError(t, createErr)
	require.NotEmpty(t, crsfToken)

	var validationErr = manager.Validate("1", crsfToken)
	require.NoError(t, validationErr, "failed to validate token")

	validationErr = manager.Validate("2", crsfToken)
	require.Error(t, validationErr)
}
