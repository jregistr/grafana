+++
title = "JWT Auth"
description = "Grafana JWT Guide"
keywords = ["grafana", "configuration", "documentation", "jwt", "jwt auth", "auth"]
type = "docs"
[menu.docs]
name = "JWT"
identifier = "jwt_auth"
parent = "authentication"
weight = 6
+++

# JWT Authentication

[JSON Web Tokens](https://jwt.io/) are an open, industry standard [RFC 7519](https://tools.ietf.org/html/rfc7519) method for representing claims securely between two parties.

Grafana can use JWT tokens for authentication.


```bash
[auth.jwt]
enabled = false
header = X-Your-JWT-Header

# Verification key locator. This config value can be either:
# 1. URL: E.g https://www.gstatic.com/iap/verify/public_key-jwk. Grafana will send GET requests to this url.
# 2. File: E.g /var/lib/grafana/yourkeyfile
# 3. String: directly set the key value.

# The content will be checked for:
# 1. Keys within a JWK (https://tools.ietf.org/html/rfc7517) structure
# 2. Keys within a JSON structure pairing an ID to a RSA Public Key PEM. e.g. {"id" : "-----BEGIN CERTIFICATE---"}
# 3. Base64 encoded bytes
# 4. raw key bytes
verification = {url | path to file | string}

# Interval time before reloading the verification file.
# https://golang.org/pkg/time/#ParseDuration
verification_ttl = 6h

# A mapping of the expected claim value(s) in the JWT payload.
# This value can be expressed in two ways:
# 1. As a series of space separated key value pairs. E.g. expect_claims = key:value key:value
# 2. As a JSON string. E.g.
# expect_claims = {
# "key1": "value", "key2" : "value2"}
expect_claims =

# The claim that may be used for the login username.
# If this field is not configured, the "email_claim" config will be used instead as the login name.
login_claim =

# Check for an email address at this claim
email_claim = email

# Set to true if users should be auto created when the JWT is valid but there isn't an existing user for this login.
auto_signup = true
```

## Example Configurations

### Google IAP

When deployed in Google Cloud with a Load Balancer having [IAP](https://cloud.google.com/iap) enabled,
Grafana can be configured to check the signed JWT header. See the IAP [How to Guide](https://cloud.google.com/iap/docs/signed-headers-howto) for
details on how to configure claim verification.


```bash
[auth.jwt]
enabled = true
header = x-goog-iap-jwt-assertion
verification = https://www.gstatic.com/iap/verify/public_key-jwk
verification_ttl = 6h
expect_claims = {\
  "aud": "/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID", \
  "iss": "https://cloud.google.com/iap" }
email_claim = email
auto_signup = true
```



### Firebase

Grafana can be configured to verify the ID token header sent by a Firebase Application. See the Firebase [Verify Id Tokens](https://firebase.google.com/docs/auth/admin/verify-id-tokens) guide
for more details.

```bash
[auth.jwt]
enabled = true
header = X-Your-JWT-Header
verification = https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
verification_ttl = 6h
expect_claims = iss:https://securetoken.google.com/{your_project}
email_claim = email
auto_signup = true
```

