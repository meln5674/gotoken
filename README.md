# GoToken

This is a small library of utilities for dealing with JSON Web Tokens (JWT) in Golang APIs.

This library provides 6 ways of obtaining tokens:

* As the literal value of a specified header
* As the token part of an "Authorization: Bearer XXX" header
* As the Username of an "Authorization: Basic" header
* As the Password of an "Authorization: Basic" header
* From a lookup table using a client certificate provided from an HTTPS request's TLS context
* From a lookup table using a client certificate provided as a header set by a TLS terminating proxy (e.g nginx)

APIs can use this library to provide OIDC RBAC support with minimal effort.
