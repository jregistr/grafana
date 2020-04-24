package util

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"testing"
	"time"

	"os"
)

var (
	mockClientSwitch bool = false
)

type mockHttpClient struct {
}

// Do is the mock client's `Do` func
func (mc *mockHttpClient) Do(_ *http.Request) (*http.Response, error) {
	pwd, _ := os.Getwd()
	var fn = pwd + "/jwt_test_data.firebase.json"
	println(fn)
	if mockClientSwitch {
		fn = pwd + "/jwt_test_data.google.json"
	}

	file, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	resp := http.Response{Body: file, Status: http.StatusText(http.StatusOK), StatusCode: http.StatusOK}

	return &resp, nil
}

func TestJWTUtils(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal("Unable to get working directory", err)
	}

	// Expired Token from google IAP for App Engine
	googleIapJwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImI5dlRMQSJ9.eyJhdWQiOiIvcHJvamVjdHMvNzgzMjk1MjYxNjMzL2FwcHMvamVmZi1wZXJzb25hbC1zaXRlIiwiZW1haWwiOiJqZWZmc3Rlc3RpbmdlbWFpbEBnbWFpbC5jb20iLCJleHAiOjE1ODY3NDg1NjEsImlhdCI6MTU4Njc0Nzk2MSwiaXNzIjoiaHR0cHM6Ly9jbG91ZC5nb29nbGUuY29tL2lhcCIsInN1YiI6ImFjY291bnRzLmdvb2dsZS5jb206MTE1NzQ3MDExMzkyODYyNTE4NTQxIn0.VBV_yGpCWcCSTbHq1gd4ooWq_jee9wExbSnB_OK0e36X4F6MUnWWBMuLWEjmgHwkZifGbJ2t9vsZgeeU4SMkJg"

	// Expired token (using kid=97fcbca368fe77808830c8100121ec7bde22cf0e)
	firebaseJwtToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk3ZmNiY2EzNjhmZTc3ODA4ODMwYzgxMDAxMjFlYzdiZGUyMmNmMGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbW9uaXRyb24tZGV2IiwibmFtZSI6IlJ5YW4gTWNLaW5sZXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDYuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1WVVZEODZxRzZkQS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFCRS9JV1VfbXdBdV9HSS9waG90by5qcGciLCJhdWQiOiJtb25pdHJvbi1kZXYiLCJhdXRoX3RpbWUiOjE1NDM0MzkyMTcsInVzZXJfaWQiOiJ3SDJXelhOS0dHUnRaZzl5bVRlS0tYbTlOaGIyIiwic3ViIjoid0gyV3pYTktHR1J0Wmc5eW1UZUtLWG05TmhiMiIsImlhdCI6MTU1MDAxNDg2MiwiZXhwIjoxNTUwMDE4NDYyLCJlbWFpbCI6InJ5YW5AbmF0ZWxlbmVyZ3kuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDg0NzkxMjI2MjIxNjMzOTU5NTgiXSwiZW1haWwiOlsicnlhbkBuYXRlbGVuZXJneS5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.Yil2QL1leIITBJIS4m8-SDdgMSv6oIvp5gPZqAvYSAzShkGauIAcmaSG0CRh4AzjdqaLafpw7_t9ihADTV-h7HPXJjzxBWS9HQ1ZW8ndOSTGl9FDYn2CC0jrFjWjqip4HVKQr88tt8idYMGk-eThNfGl3AmJw-AUvj-zMfxbQCGM6Kskj5kYvmsHy2UL5aeM8VNPQF19BBIfquSP8nrv12G79ntdrh60ikosw8Vi7lG-LuFC2XLJzgH0_Z7dHPH8fH-51HQHYgcxJ0-Zt7mXmOWcinqp2UPS0ZeUmMEwHQkA_5gB9_ZT900e5LRz5d3N95FqbZrJh0p5qSnU8WSwtg"

	t.Run("Test reading Google JWK json", func(t *testing.T) {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.google.json")
		assert.True(t, decoder.CheckReady())
	})

	t.Run("Test reading Google firebase Key set", func(t *testing.T) {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.firebase.json")
		assert.True(t, decoder.CheckReady())
	})

	t.Run("Test reading Google IAP Jwt string", func(t *testing.T) {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.google.json")
		assert.True(t, decoder.CheckReady())

		key, err := decoder.Decode(googleIapJwt)

		assert.Equal(t, "jeffstestingemail@gmail.com", key["email"])

		assert.NotNil(t, err)
		assert.Equal(t, JWT_ERROR_Expired, err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)

		t.Run("that Now() returns a time where the token is valid", func(t *testing.T) {
			TimeNow = func() time.Time {
				return time.Unix(1586748011, 0)
			}

			key, err := decoder.Decode(googleIapJwt)
			assert.Nil(t, err)
			assert.NotNil(t, key)
			assert.Equal(t, "jeffstestingemail@gmail.com", key["email"])

			t.Run("The Decoder's Expected Issuer does not match the tokens", func(t *testing.T) {
				decoder.ExpectClaims = make(map[string]string)
				decoder.ExpectClaims["iss"] = "https://securetoken.google.com/obviously-wrong.com"

				key, err := decoder.Decode(googleIapJwt)
				assert.NotNil(t, err)
				assert.Equal(t, JWT_ERROR_Unexpected, err.Code)
				assert.Equal(t, "https://cloud.google.com/iap", key["iss"])
			})
		})
	})

	t.Run("Test reading firebase tokens", func(t *testing.T) {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.firebase.json")
		assert.True(t, decoder.CheckReady())

		key, err := decoder.Decode(firebaseJwtToken)

		assert.Equal(t, "ryan@natelenergy.com", key["email"])
		assert.NotNil(t, err)
		assert.Equal(t, JWT_ERROR_Expired, err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)

		t.Run("Given a Now() function that returns a time making the token valid", func(t *testing.T) {
			decoder.ExpectClaims = make(map[string]string)

			TimeNow = func() time.Time {
				return time.Unix(1543439217, 0) // Make the time OK
			}

			key, err = decoder.Decode(firebaseJwtToken)
			assert.Nil(t, err)

			t.Run("Given a Decoder whose Expected claim won't match the tokens's own", func(t *testing.T) {
				decoder.ExpectClaims["iss"] = "https://securetoken.google.com/monitron-devX"
				key, err = decoder.Decode(firebaseJwtToken)
				assert.NotNil(t, key)
				assert.NotNil(t, err)
				assert.Equal(t, JWT_ERROR_Unexpected, err.Code)
				assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)
			})
		})
	})

	t.Run("A decoder with a mocked http source", func(t *testing.T) {
		HttpClient = &mockHttpClient{}
		decoder := NewJWTDecoder("http://fake-site.com")
		decoder.TTL = 5 * time.Minute
		assert.True(t, decoder.CheckReady())

		keys := decoder.keys.getVerificationKeys(jose.Header{KeyID: "97fcbca368fe77808830c8100121ec7bde22cf0e"})
		assert.Len(t, keys, 1)

		t.Run("The mocked time has advanced 1 hour and decode is called", func(t *testing.T) {
			mockClientSwitch = true
			TimeNow = func() time.Time {
				return time.Now().Add(1 * time.Hour)
			}

			key, err := decoder.Decode(googleIapJwt)
			assert.NotNil(t, err)
			assert.NotNil(t, key)
			assert.Equal(t, JWT_ERROR_Expired, err.Code)

			t.Run("Checking the keys inside the decoder", func(t *testing.T) {
				keys := decoder.keys.getVerificationKeys(jose.Header{KeyID: "2nMJtw"})
				assert.Len(t, keys, 1)
			})
		})
	})

}
