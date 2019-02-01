package middleware

import (
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httptest"
	"testing"

	macaron "gopkg.in/macaron.v1"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthJWT(t *testing.T) {
	Convey("When using JWT auth", t, func() {

		orgId := int64(1)
		bus.ClearBusHandlers()
		bus.AddHandler("test", func(query *m.GetSignedInUserQuery) error {
			query.Result = &m.SignedInUser{OrgId: orgId, UserId: 123}
			return nil
		})

		fmt.Println("runing first test")

		// A simple key
		mySigningKey := []byte("AllYourBase")
		setting.AuthJwtEnabled = true
		setting.AuthJwtHeader = "X-MyJWT"
		setting.AuthJwtSigningKey = base64.StdEncoding.EncodeToString(mySigningKey)
		setting.AuthJwtEmailClaim = "email"

		// Create the Claims
		claims := &jwt.MapClaims{
			"sub":   "name",
			"email": "test@grafana.com",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(mySigningKey)
		So(err, ShouldEqual, nil)
		InitAuthJwtKey()

		Convey("Should be able to decode directly", func() {
			token, err := jwt.Parse(signed, keyFunc)
			So(err, ShouldEqual, nil)
			So(token.Valid, ShouldEqual, true)

			parsed := token.Claims.(jwt.MapClaims)
			So(parsed["email"], ShouldEqual, "test@grafana.com")
			So(parsed["sub"], ShouldEqual, "name")
		})

		Convey("Context should read it from header and get a user", func() {
			httpreq := &http.Request{Header: make(http.Header)}
			httpreq.Header.Add(setting.AuthJwtHeader, signed)

			ctx := &m.ReqContext{Context: &macaron.Context{
				Req:  macaron.Request{Request: httpreq},
				Resp: macaron.NewResponseWriter("POST", httptest.NewRecorder()),
			},
				Logger: log.New("fakelogger"),
			}

			initContextWithJwtAuth(ctx, orgId)
			So(ctx.SignedInUser, ShouldNotBeNil)
		})

		Convey("Should parse firebase tokens", func() {

			// Firebase public keys
			setting.AuthJwtSigningKey = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
			setting.AuthJwtIssuer = "https://securetoken.google.com/safetronx"
			InitAuthJwtKey()
			So(keyFunc, ShouldNotBeNil)

			// Expired token
			fbjwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg1OWE2NDFhMWI4MmNjM2I1MGE4MDFiZjUwNjQwZjM4MjU3ZDEyOTkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc2FmZXRyb254IiwibmFtZSI6IlJ5YW4gTWNLaW5sZXkiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDUuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy12M0diUy1namhlcy9BQUFBQUFBQUFBSS9BQUFBQUFBQUNIZy94ZE5VbDRmMUdEZy9waG90by5qcGciLCJhdWQiOiJzYWZldHJvbngiLCJhdXRoX3RpbWUiOjE1NDkwNDIzNzUsInVzZXJfaWQiOiJyalNaZm9LYnZYU1pyRGg3SUVmOGRid0Mxa2kxIiwic3ViIjoicmpTWmZvS2J2WFNackRoN0lFZjhkYndDMWtpMSIsImlhdCI6MTU0OTA0MjM3NSwiZXhwIjoxNTQ5MDQ1OTc1LCJlbWFpbCI6InJ5YW50eHVAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDM3Nzg4NDE3Nzk5OTQ4ODI1MTIiXSwiZW1haWwiOlsicnlhbnR4dUBnbWFpbC5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJnb29nbGUuY29tIn19.YPgqDMZAXUQPPR3ofDBl4vIK1amQQLsmo9OQvM0v9f98hDWcwVIPBh34CWFum40DA-H6JDqiGMbqcPl8LPUewRU01GdbR1QV7FvL_n2UQOLSJWcRnyi-LBK2TtkQ6fRpNNrX-E3lwgNq_GnegkEW1NZnPqpLZsN67kflGh5c7tC45v0osvFT-X8LjWxww4PijoZZsTdF2GRkuRYGLWQ1v99dhr9y8QhXHtTiHS6D9bjZ53K7t8CBKiZ5Ibkr4wZhz5-mW-6PibzTX-u2JeIzQFZo9tQM7-T526oVU19d7O-P5PU_kNmHe99PyDt2drtBbUPNn9IeenvIrz6rOKau6g"

			token, err := jwt.Parse(fbjwt, keyFunc)
			if token.Valid {
				So(token.Valid, ShouldEqual, true)
			} else {
				So(err, ShouldNotEqual, nil)
				So(token.Valid, ShouldEqual, false)
			}
			parsed := token.Claims.(jwt.MapClaims)

			So(parsed["email"], ShouldEqual, "ryantxu@gmail.com")
			So(parsed["email_verified"], ShouldBeTrue)

			fmt.Printf("FIREBASE: %+v\n", parsed)
		})
	})
}
