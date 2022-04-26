package campid

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestActionPolicy(t *testing.T) {
	t.Run("Format", func(t *testing.T) {
		require.Equal(t, "READ::Admin.createPage", CreateActionPolicy(ReadPermission, "Admin.createPage"))
	})
}
