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

	t.Run("Test Cloudflare Access Support", func(t *testing.T) {
		
		cloudflareJwkPath := pwd + "/jwt_test_data.cloudflareaccess.json"
		cloduflareAccessJwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiZjczYzdhNjcxMjI1ODQyOGRkNjI1YmU4ZGExZjY2NjBiNzRkOWExMGQ4ODc3ZjU3OWY4NDI5NDkwYmFhM2E2NCJdLCJlbWFpbCI6InRlc3RAZ21haWwuY29tIiwiZXhwIjoxNTg3OTAwMzQ1LCJpYXQiOjE1ODc4OTY3NDUsImlzcyI6ImdyYWZhbmF0ZXN0IiwianRpIjoiZndKODFXUWE0d0tSMHdUT24yMThnUSIsIm5iZiI6MTU4Nzg5Njc0NX0.eqo8r4rdF_v-lf39IIM29Q6BqgxB9i8B4qhXc428sVIo4UBw9nWK1A5VOhus_UVbNVLqX15QrFamHbCasAha0ZUflp6nuW9AJIt1GXo2y3U_DbJDKIuJfVj-299kyj5FI6RSG-QlWGinb-NEeKMXUNi_-OXnkH70nH2T4PvJ_kaQBs4bM06gOBUO33UNkf8yCYaMGr3F_WlNqq1MoyPMXn77lO9i9RCOI-vnpfxYD96RfkYshNqrlM3Veq__ZydN0NBVzauvVDuxPdbZdJixZ7xYSlwL7DAp9_U9GFBzC5ieV2PKU7_qHStJ-IHAzqmawji4ZlMkGLrZpEW0AMhAnCp4rQNtT0Kowk6gLGaKCfe-92KwGsDYzeIeII--aMB7H72x9uiqqz9FK0zVb46KsD4ZGC9_cCYkcO1InVBYddKEQiqv7OrZ33lxe7Y6LzltO5sDl0BF8HaA34vHAqMerK90A1cZBOYVgO547CQx9JSX24nZ47-U0_ZgtUMvxwwiAe9_1zfjxpDT_QnYn2fuwTXUpjWfZF05ei2NRuUh0WUKwwHa4V-4uPyDvL0Mg_iMjzB1wjQwS_xXDKQdl95prc2BLivdzmBemP79ClGFQHcSj9tBTbQn9svNxXok8oiEJGNVVkdlu4Mz9elP8jWeqNNTuOySEnu7w2dtX0G-NiQ"

		jwtAudience := "f73c7a6712258428dd625be8da1f6660b74d9a10d8877f579f8429490baa3a64"
		jwtExpireTime, e := time.Parse(time.RFC3339, "2020-04-26T11:25:45+00:00")
		assert.Nil(t, e, "No errors should happen parsing the time")
	
		timeBeforeExpire := jwtExpireTime.Add(-10 * time.Minute)
		timeAfterExpire := jwtExpireTime.Add(10 * time.Minute)

		t.Run("Should be able to read JWK", func(t *testing.T) {
			decoder := NewJWTDecoder(cloudflareJwkPath)
			assert.True(t, decoder.CheckReady())
		})

		t.Run("Should authorize with a valid and matching JWT", func(t *testing.T) {
			decoder := NewJWTDecoder(cloudflareJwkPath)
			decoder.ExpectClaims = make(map[string]string)
			decoder.ExpectClaims["aud"] = jwtAudience
			assert.True(t, decoder.CheckReady())

			TimeNow = func() time.Time {
				return timeBeforeExpire
			}

			key, err := decoder.Decode(cloduflareAccessJwt)
	
			assert.Equal(t, "test@gmail.com", key["email"])
			assert.Nil(t, err)
		})

		t.Run("Should not authorize with a non matching JWT", func(t *testing.T) {
			decoder := NewJWTDecoder(cloudflareJwkPath)
			decoder.ExpectClaims = make(map[string]string)
			decoder.ExpectClaims["aud"] = "someotheraudiencethatdoesnotmatchthejwtaudclaim"
			assert.True(t, decoder.CheckReady())

			TimeNow = func() time.Time {
				return timeBeforeExpire
			}

			_, err := decoder.Decode(cloduflareAccessJwt)
	
			assert.NotNil(t, err)
			assert.Equal(t, JWT_ERROR_Unexpected, err.Code)
			assert.Equal(t, "Mismatch: aud", err.msg)
		})

		t.Run("Should not authorize with a expired JWT", func(t *testing.T) {
			decoder := NewJWTDecoder(cloudflareJwkPath)
			decoder.ExpectClaims = make(map[string]string)
			decoder.ExpectClaims["aud"] = jwtAudience
			assert.True(t, decoder.CheckReady())

			TimeNow = func() time.Time {
				return timeAfterExpire
			}

			_, err := decoder.Decode(cloduflareAccessJwt)
	
			assert.NotNil(t, err)
			assert.Equal(t, JWT_ERROR_Expired, err.Code)
		})

		t.Run("Should not authorize with a invalid JWT", func(t *testing.T) {
			decoder := NewJWTDecoder(cloudflareJwkPath)
			assert.True(t, decoder.CheckReady())

			invalidJWT := firebaseJwtToken
			_, err := decoder.Decode(invalidJWT)
	
			assert.NotNil(t, err)
			assert.Equal(t, JWT_ERROR_UnknownKey, err.Code)
		})
	})
}