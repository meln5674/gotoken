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

type Robot struct {
	Name  string
	Cert  *x509.Certificate
	Token *jwt.Token
}

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

func GetRobotCertHTTPS(req *http.Request) (*x509.Certificate, bool, error) {
	if len(req.TLS.PeerCertificates) == 0 {
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

func MakeRobotLookupTable(robots []Robot) RobotLookupTable {
	robotsByCert := make(map[string]Robot, len(robots))
	for _, robot := range robots {
		robotsByCert[GetCertificateLookupKey(robot.Cert)] = robot
	}
	return RobotLookupTable(robotsByCert)
}

func (t RobotLookupTable) Lookup(cert *x509.Certificate) (Robot, bool) {
	robot, ok := t[GetCertificateLookupKey(cert)]
	return robot, ok
}
