package gotoken

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

// ErrNoSuchRobot is returned from a robot token getter if a certificate is provided that matches no robots
var ErrNoSuchRobot = errors.New("No such robot")

// A Robot is a mapping from a mTLS certificate to a fake JWT with the claims to grant to a
// connection that authenticates using that certificate's private key.
// Because the certificate can be publicly distributed, Robot's should be used when the robot operator
// does not want to expose their secrets to the app operator.
type Robot struct {
	Name  string
	Cert  *x509.Certificate
	Token *jwt.Token
}

// GetRobotCertHTTP assumes that an mTLS connection has been terminated by a proxy, and retrieves the encoded certificate from a header
func GetRobotCertHTTP(name string, req *http.Request) (*x509.Certificate, bool, error) {
	certStringEsc := req.Header.Get(name)
	if certStringEsc == "" {
		return nil, false, nil
	}
	certString, err := url.QueryUnescape(certStringEsc)
	if err != nil {
		return nil, true, errors.Wrap(err, "Invalid url-encoded certificate in header")
	}
	der, rest := pem.Decode([]byte(certString))
	if der == nil {
		return nil, true, fmt.Errorf("No PEM data found in cert header")
	}
	if len(rest) != 0 {
		return nil, true, fmt.Errorf("Trailing data after PEM certificate cert header")
	}
	cert, err := x509.ParseCertificate(der.Bytes)
	return cert, true, err
}

// GetRobotCertHTTPS assumes the mTLS is natively handled by the app in question, and obtains the first peer certificate
func GetRobotCertHTTPS(req *http.Request) (*x509.Certificate, bool, error) {
	if req.TLS == nil {
		fmt.Printf("Not a TLS request\n")
		return nil, false, fmt.Errorf("Not a TLS request")
	}
	if len(req.TLS.PeerCertificates) == 0 {
		fmt.Printf("No peer certs\n")
		return nil, false, nil
	}
	return req.TLS.PeerCertificates[0], true, nil

}

func GetRobotCert(name string, https bool, req *http.Request) (*x509.Certificate, bool, error) {
	if https {
		return GetRobotCertHTTPS(req)
	}
	return GetRobotCertHTTP(name, req)
}

type RobotLookupTable map[string]Robot

func GetCertificateLookupKey(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// MakeRobotLookupTables takes a set of robots and produces an O(1) lookup table mapping their certificates to their JWTs
func MakeRobotLookupTable(robots []Robot) RobotLookupTable {
	robotsByCert := make(map[string]Robot, len(robots))
	for _, robot := range robots {
		robotsByCert[GetCertificateLookupKey(robot.Cert)] = robot
	}
	return RobotLookupTable(robotsByCert)
}

// Lookup attempts to get the JWT associated with a robot's certificate
func (t RobotLookupTable) Lookup(cert *x509.Certificate) (Robot, bool) {
	key := GetCertificateLookupKey(cert)
	robot, ok := t[key]
	if !ok {
		fmt.Printf("Got unknown robot cert key %s\n", key)
	} else {
		fmt.Printf("Got robot %#v (%#v) with key %s", robot, robot.Token, key)
	}
	return robot, ok
}
