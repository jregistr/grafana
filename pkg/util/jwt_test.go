package util

import (
	"net/http"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"os"
)

func TestJWTUtils(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal("Unable to get working directory", err)
	}

	// Expired Token from google IAP for App Engine
	googleIapJwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImI5dlRMQSJ9.eyJhdWQiOiIvcHJvamVjdHMvNzgzMjk1MjYxNjMzL2FwcHMvamVmZi1wZXJzb25hbC1zaXRlIiwiZW1haWwiOiJqZWZmc3Rlc3RpbmdlbWFpbEBnbWFpbC5jb20iLCJleHAiOjE1ODY3NDg1NjEsImlhdCI6MTU4Njc0Nzk2MSwiaXNzIjoiaHR0cHM6Ly9jbG91ZC5nb29nbGUuY29tL2lhcCIsInN1YiI6ImFjY291bnRzLmdvb2dsZS5jb206MTE1NzQ3MDExMzkyODYyNTE4NTQxIn0.VBV_yGpCWcCSTbHq1gd4ooWq_jee9wExbSnB_OK0e36X4F6MUnWWBMuLWEjmgHwkZifGbJ2t9vsZgeeU4SMkJg"

	// Expired token (using kid=97fcbca368fe77808830c8100121ec7bde22cf0e)
	firebaseJwtToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk3ZmNiY2EzNjhmZTc3ODA4ODMwYzgxMDAxMjFlYzdiZGUyMmNmMGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vbW9uaXRyb24tZGV2IiwibmFtZSI6IlJ5YW4gTWNLaW5sZXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDYuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1WVVZEODZxRzZkQS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFCRS9JV1VfbXdBdV9HSS9waG90by5qcGciLCJhdWQiOiJtb25pdHJvbi1kZXYiLCJhdXRoX3RpbWUiOjE1NDM0MzkyMTcsInVzZXJfaWQiOiJ3SDJXelhOS0dHUnRaZzl5bVRlS0tYbTlOaGIyIiwic3ViIjoid0gyV3pYTktHR1J0Wmc5eW1UZUtLWG05TmhiMiIsImlhdCI6MTU1MDAxNDg2MiwiZXhwIjoxNTUwMDE4NDYyLCJlbWFpbCI6InJ5YW5AbmF0ZWxlbmVyZ3kuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDg0NzkxMjI2MjIxNjMzOTU5NTgiXSwiZW1haWwiOlsicnlhbkBuYXRlbGVuZXJneS5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.Yil2QL1leIITBJIS4m8-SDdgMSv6oIvp5gPZqAvYSAzShkGauIAcmaSG0CRh4AzjdqaLafpw7_t9ihADTV-h7HPXJjzxBWS9HQ1ZW8ndOSTGl9FDYn2CC0jrFjWjqip4HVKQr88tt8idYMGk-eThNfGl3AmJw-AUvj-zMfxbQCGM6Kskj5kYvmsHy2UL5aeM8VNPQF19BBIfquSP8nrv12G79ntdrh60ikosw8Vi7lG-LuFC2XLJzgH0_Z7dHPH8fH-51HQHYgcxJ0-Zt7mXmOWcinqp2UPS0ZeUmMEwHQkA_5gB9_ZT900e5LRz5d3N95FqbZrJh0p5qSnU8WSwtg"

	Convey("Test reading Google JWK json", t, func() {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.google.json")
		So(decoder.CheckReady(), ShouldBeTrue)
	})

	Convey("Test reading Google firebase Key set", t, func() {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.firebase.json")
		So(decoder.CheckReady(), ShouldBeTrue)
	})

	Convey("Test reading Google IAP Jwt string", t, func() {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.google.json")
		So(decoder.CheckReady(), ShouldBeTrue)

		key, errDecoding := decoder.Decode(googleIapJwt)

		So(key["email"], ShouldEqual, "jeffstestingemail@gmail.com")

		So(errDecoding, ShouldNotBeNil)
		So(errDecoding.Code, ShouldEqual, JWT_ERROR_Expired)
		So(http.StatusUnauthorized, ShouldEqual, errDecoding.HttpStatusCode)

		Convey("that Now() returns a time where the token is valid", func() {
			decoder.Now = func() time.Time {
				return time.Unix(1586748011, 0)
			}

			key, errDecoding := decoder.Decode(googleIapJwt)
			So(errDecoding, ShouldBeNil)
			So(key, ShouldNotBeNil)
			So(key["email"], ShouldEqual, "jeffstestingemail@gmail.com")

			Convey("The Decoder's Expected Issuer does not match the tokens", func() {
				decoder.ExpectClaims = make(map[string]string)
				decoder.ExpectClaims["iss"] = "https://securetoken.google.com/obviously-wrong.com"

				key, errDecoding := decoder.Decode(googleIapJwt)
				So(errDecoding, ShouldNotBeNil)
				So(errDecoding.Code, ShouldEqual, JWT_ERROR_Unexpected)
				So(key["iss"], ShouldEqual, "https://cloud.google.com/iap")
			})
		})
	})

	Convey("Test reading firebase tokens", t, func() {
		decoder := NewJWTDecoder(pwd + "/jwt_test_data.firebase.json")
		So(decoder.CheckReady(), ShouldBeTrue)

		key, err := decoder.Decode(firebaseJwtToken)

		So(key["email"], ShouldEqual, "ryan@natelenergy.com")
		So(err, ShouldNotBeNil)
		So(err.Code, ShouldEqual, JWT_ERROR_Expired)
		So(http.StatusUnauthorized, ShouldEqual, err.HttpStatusCode)

		Convey("Given a Now() function that returns a time making the token valid", func() {
			decoder.ExpectClaims = make(map[string]string)

			decoder.Now = func() time.Time {
				return time.Unix(1543439217, 0) // Make the time OK
			}

			key, err = decoder.Decode(firebaseJwtToken)
			So(err, ShouldBeNil)

			Convey("Given a Decoder whose Expected claim won't match the tokens's own", func() {
				decoder.ExpectClaims["iss"] = "https://securetoken.google.com/monitron-devX"
				key, err = decoder.Decode(firebaseJwtToken)
				So(key, ShouldNotBeNil)
				So(err, ShouldNotBeNil)
				So(err.Code, ShouldEqual, JWT_ERROR_Unexpected)
				So(http.StatusUnauthorized, ShouldEqual, err.HttpStatusCode)
			})
		})
	})

}
