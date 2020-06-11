package setting

import (
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"

)

func TestJwtAuthSettings(t *testing.T) {
	
	t.Run("Test reading JWT auth configuration values from .ini file", func(t *testing.T) {
		homePath := "../../"
		t.Run("If expected claims are configured as JSON - should return value from ini file", func(t *testing.T) {
			cfg := NewCfg()
			err := cfg.Load(&CommandLineArgs{
				HomePath: homePath,
				Config:   filepath.Join(homePath, "pkg/setting/testdata/jwtauthconfig_json_claims.ini"),
			})
			assert.Nil(t, err)

			claims := make(map[string]string)
			claims["aud"] = "testaudience"
			claims["iss"] = "https://someurl"

			assert.Equal(t, claims, AuthJwtExpectClaims)
		})

		t.Run("If expected claims are configured as key:value - should return value from ini file", func(t *testing.T) {
			cfg := NewCfg()
			err := cfg.Load(&CommandLineArgs{
				HomePath: homePath,
				Config:   filepath.Join(homePath, "pkg/setting/testdata/jwtauthconfig_keyvalue_claims.ini"),
			})
			assert.Nil(t, err)

			claims := make(map[string]string)
			claims["aud"] = "otheraudience"
			claims["iss"] = "https://someotherurl"

			assert.Equal(t, claims, AuthJwtExpectClaims)
		})

	})
}
