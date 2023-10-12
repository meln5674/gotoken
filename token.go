package gotoken

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

const (
	// HeaderAuthorization is the name of the header to obtain the bearer token from
	HeaderAuthorization = "Authorization"
	// HeaderAuthorizationBearerPrefix is the prefix to the Authorization header if it contains a bearer token
	HeaderAuthorizationBearerPrefix = "Bearer "
)

// TokenMode is the method used to extract a token from an HTTP(S) request
type TokenMode = string

const (
	// TokenModeRaw interpretes a header as a literal token
	TokenModeRaw TokenMode = "raw"
	// TokenModeBearer takes the token from an "Authorization: Bearer XXX" header
	TokenModeBearer TokenMode = "bearer"
	// TokenModeBasic takes the token from the username of an "Authorization: Basic XXX" header
	TokenModeBasicUser TokenMode = "basic-user"
	// TokenModeBasic takes the token from the password of an "Authorization: Basic XXX" header
	TokenModeBasicPassword TokenMode = "basic-password"
	// TokenModeBasic takes the token from a lookup table of trusted service account mTLS client certificate
	TokenModeRobotTLS TokenMode = "robot-tls"
	// TokenModeBasic takes the token from a lookup table of trusted service account mTLS client certificate taken from a header
	TokenModeRobotTLSTerminated TokenMode = "robot-tls-terminated"
	// TokenModeSymmetricRobot takes an opaque token from a nested token extractor and maps it to a JWT from a lookup table
	TokenModeSymmetricRobot TokenMode = "symmetric-robot"
	// TokenModeOIDCCookie looks first for an oidc callback code, and if not present, checks for a signed cookie containing the token
	TokenModeOIDCCookie TokenMode = "oidc-cookie"
)

// A TokenGetter can extract a token from a request. Return patterns:
// nil, false, nil - No token material was present
// nil, true, err - Token material present but invalid
// token, true, nil - Token present and valid
// Functions must not return an error if that error indicates that the material cannot be obtained or is not present.
type TokenGetter func(req *http.Request) (token *jwt.Token, present bool, err error)

// A TokenStringGetter can extract a token string from a request, but does not parse or validate it.
// If the token is not present, it should return an empty string
type TokenStringGetter func(req *http.Request) string

type TokenGetterChain struct {
	Getters         []TokenGetter
	ContinueOnError bool
}

func (t *TokenGetterChain) Getter() TokenGetter {
	return func(req *http.Request) (token *jwt.Token, present bool, err error) {
		for _, getter := range t.Getters {
			fmt.Printf("Trying token getter %#v\n", getter)
			token, present, err := getter(req)
			if present && (err == nil || !t.ContinueOnError) {
				return token, present, err
			}
		}
		// TODO: multi-error
		return nil, false, nil
	}
}

type TokenGetterArgs struct {
	HeaderName               string
	LookupTable              RobotLookupTable
	SymmetricLookupTable     SymmetricRobotLookupTable
	SymmetricSecretGetter    TokenStringGetter
	Keyfunc                  jwt.Keyfunc
	InsecureSkipVerification bool
	Parser                   *jwt.Parser
}

func (t *TokenGetterArgs) Secure(keyfunc jwt.Keyfunc) *TokenGetterArgs {
	t.InsecureSkipVerification = false
	t.Keyfunc = keyfunc
	return t
}

func (t *TokenGetterArgs) Insecure() *TokenGetterArgs {
	t.InsecureSkipVerification = true
	t.Keyfunc = nil
	return t
}

func (t *TokenGetterArgs) Raw(headerName string, parser *jwt.Parser) (TokenMode, *TokenGetterArgs) {
	t.HeaderName = headerName
	t.Parser = parser
	return TokenModeRaw, t
}

func (t *TokenGetterArgs) Bearer(parser *jwt.Parser) (TokenMode, *TokenGetterArgs) {
	t.Parser = parser
	return TokenModeBearer, t
}

func (t *TokenGetterArgs) BasicUser(parser *jwt.Parser) (TokenMode, *TokenGetterArgs) {
	t.Parser = parser
	return TokenModeBasicUser, t
}

func (t *TokenGetterArgs) BasicPassword(parser *jwt.Parser) (TokenMode, *TokenGetterArgs) {
	t.Parser = parser
	return TokenModeBasicPassword, t
}

func (t *TokenGetterArgs) RobotTLSTerminated(headerName string, lookupTable RobotLookupTable) (TokenMode, *TokenGetterArgs) {
	t.HeaderName = headerName
	t.LookupTable = lookupTable
	return TokenModeRobotTLSTerminated, t
}

func (t *TokenGetterArgs) RobotTLS(lookupTable RobotLookupTable) (TokenMode, *TokenGetterArgs) {
	t.LookupTable = lookupTable
	return TokenModeRobotTLS, t
}

func (t *TokenGetterArgs) SymmetricRobot(lookupTable SymmetricRobotLookupTable, getter TokenStringGetter) (TokenMode, *TokenGetterArgs) {
	t.SymmetricLookupTable = lookupTable
	t.SymmetricSecretGetter = getter
	return TokenModeSymmetricRobot, t
}

func GetTokenStringGetter(mode TokenMode, args *TokenGetterArgs) (TokenStringGetter, bool) {
	switch mode {
	case TokenModeRaw:
		return GetRawTokenString(args.HeaderName), true
	case TokenModeBearer:
		return GetBearerTokenString(), true
	case TokenModeBasicUser:
		return GetBasicUserTokenString(), true
	case TokenModeBasicPassword:
		return GetBasicPasswordTokenString(), true
	}
	return nil, false
}

func GetTokenGetter(mode TokenMode, args *TokenGetterArgs) (TokenGetter, bool) {
	switch mode {
	case TokenModeRaw, TokenModeBearer, TokenModeBasicUser, TokenModeBasicPassword:
		getter, ok := GetTokenStringGetter(mode, args)
		if !ok {
			panic("BUG: Mismatch between GetTokenGetter and GetTokenStringGetter")
		}
		return FromStringGetter(getter, args.Parser, args.InsecureSkipVerification, args.Keyfunc), true
	case TokenModeRobotTLS:
		return GetRobotTLSToken(args.LookupTable), true
	case TokenModeRobotTLSTerminated:
		return GetRobotTLSTerminatedToken(args.HeaderName, args.LookupTable), true
	case TokenModeSymmetricRobot:
		return GetSymmetricRobotToken(args.SymmetricLookupTable, args.SymmetricSecretGetter), true
	}
	return nil, false
}

func GetRawTokenString(name string) TokenStringGetter {
	return func(req *http.Request) string {
		return req.Header.Get(name)
	}
}

func GetBearerTokenString() TokenStringGetter {
	return func(req *http.Request) string {
		h := req.Header.Get(HeaderAuthorization)
		prefix := HeaderAuthorizationBearerPrefix
		if !strings.HasPrefix(h, prefix) {
			fmt.Printf("Request %#v did not have bearer token: %s\n", req, h)
			return ""
		}
		fmt.Printf("Request %#v had bearer token: %s\n", req, h)
		return strings.TrimPrefix(h, prefix)
	}
}

func GetBasicUserTokenString() TokenStringGetter {
	return func(req *http.Request) string {
		username, _, _ := req.BasicAuth()
		return username
	}
}

func GetBasicPasswordTokenString() TokenStringGetter {
	return func(req *http.Request) string {
		_, password, _ := req.BasicAuth()
		return password
	}
}

func ParseToken(s string, parser *jwt.Parser, insecure bool, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	claims := jwt.MapClaims{}
	if insecure {
		token, _, err := parser.ParseUnverified(s, claims)
		return token, err
	} else if keyFunc != nil {
		return parser.ParseWithClaims(s, claims, keyFunc)
	} else {
		return nil, fmt.Errorf("Keyfunc was null, this disables verification of JWT signatures. You must explicitly set insecure=true to do this")
	}
}

func FromStringGetter(g TokenStringGetter, parser *jwt.Parser, insecure bool, keyFunc jwt.Keyfunc) TokenGetter {
	return func(req *http.Request) (token *jwt.Token, present bool, err error) {
		tokenString := g(req)
		if tokenString == "" {
			fmt.Printf("Request produced empty token string\n")
			return nil, false, nil
		}
		fmt.Printf("Parsing request token %s\n", tokenString)
		token, err = ParseToken(tokenString, parser, insecure, keyFunc)
		return token, true, err
	}
}

func GetRobotTLSToken(robots RobotLookupTable) TokenGetter {
	return func(req *http.Request) (token *jwt.Token, present bool, err error) {
		cert, ok, err := GetRobotCertHTTPS(req)
		if !ok || err != nil {
			return nil, ok, err
		}
		robot, ok := robots.Lookup(cert)
		if !ok {
			return nil, true, ErrNoSuchRobot
		}
		return robot.Token, true, nil
	}
}

func GetRobotTLSTerminatedToken(name string, robots RobotLookupTable) TokenGetter {
	return func(req *http.Request) (token *jwt.Token, present bool, err error) {
		cert, ok, err := GetRobotCertHTTP(name, req)
		if !ok {
			return nil, false, nil
		}
		if err != nil {
			return nil, true, err
		}
		robot, ok := robots.Lookup(cert)
		if !ok {
			return nil, true, ErrNoSuchRobot
		}
		return robot.Token, true, nil
	}
}

func GetSymmetricRobotToken(robots SymmetricRobotLookupTable, g TokenStringGetter) TokenGetter {
	return func(req *http.Request) (token *jwt.Token, present bool, err error) {
		tokenString := g(req)
		if tokenString == "" {
			return nil, false, nil
		}
		robot, ok := robots.Lookup(tokenString)
		if !ok {
			return nil, true, ErrNoSuchRobot
		}
		return robot.Token, true, nil
	}
}
