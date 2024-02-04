package gotoken_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/meln5674/gotoken"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const keyString = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\nq9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n-----END PUBLIC KEY-----"
const tokenString = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA`
const symmetricTokenString = `se8BiDtp4jxgnowkekRbk3z8CsFdybJdJhWg9CxunFxTDGb5ydDe0L3BSNoKG53D`

var defaultParser = jwt.NewParser()

var parsedToken = &jwt.Token{
	Raw:    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
	Method: &jwt.SigningMethodECDSA{Name: "ES256", Hash: 5, KeySize: 32, CurveBits: 256},
	Header: map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	},
	Claims: jwt.MapClaims{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
		"iat":   1.516239022e+09,
	},
	Signature: "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
	Valid:     true,
}
var insecureParsedToken = &jwt.Token{
	Raw:    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA",
	Method: &jwt.SigningMethodECDSA{Name: "ES256", Hash: 5, KeySize: 32, CurveBits: 256},
	Header: map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	},
	Claims: jwt.MapClaims{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
		"iat":   1.516239022e+09,
	},
}

func GetTestKey(*jwt.Token) (interface{}, error) {
	key, err := jwt.ParseECPublicKeyFromPEM([]byte(keyString))
	Expect(err).ToNot(HaveOccurred())
	GinkgoWriter.Printf("key: %#v\n", key)
	return key, nil
}

func goodTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	token, present, err := getter(req)
	Expect(present).To(BeTrue())
	Expect(err).ToNot(HaveOccurred())
	expectedToken := parsedToken
	if args.InsecureSkipVerification {
		expectedToken = insecureParsedToken
	}
	Expect(token).To(Equal(expectedToken))
}

func badTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	token, present, err := getter(req)
	Expect(present).To(BeTrue())
	Expect(err).To(HaveOccurred())
	Expect(token).To(BeNil())
}

func errorTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	token, present, err := getter(req)
	Expect(present).To(BeFalse())
	Expect(err).To(HaveOccurred())
	Expect(token).To(BeNil())
}

func missingTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	token, present, err := getter(req)
	Expect(present).To(BeFalse())
	Expect(err).ToNot(HaveOccurred())
	Expect(token).To(BeNil())
}

var _ = Describe("Insecure Hardcoded Token", Ordered, func() {
	It("Should panic if the safety is on", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(func() {
			gotoken.InsecureHardcodedToken(parsedToken)(r)
		}).To(Panic())
	})
	It("Should return the token if the safety is off", func() {
		gotoken.InsecureAllowHardcodedToken = true
		DeferCleanup(func() {
			gotoken.InsecureAllowHardcodedToken = true
		})
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		t, ok, err := gotoken.InsecureHardcodedToken(parsedToken)(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(t).To(Equal(parsedToken))
	})
})

var _ = Describe("Raw Token Mode", func() {
	mode, args := (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).Raw("DummyHeader", defaultParser)
	mode2, insecureArgs := (&gotoken.TokenGetterArgs{}).Insecure().Raw("DummyHeader", defaultParser)
	Expect(mode).To(Equal(mode2))
	mode3, invalidArgs := (&gotoken.TokenGetterArgs{}).Raw("DummyHeader", defaultParser)
	Expect(mode3).To(Equal(mode3))

	It("Should reject args that did not set keyfunc or insecure=true", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("DummyHeader", tokenString)
		badTokenTest(mode, invalidArgs, r)
	})

	for _, insecure := range []bool{true, false} {
		text := ""
		if insecure {
			text = " (insecure)"
			args = insecureArgs
		}
		It("Should extract a token from a matching header"+text, func() {
			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).ToNot(HaveOccurred())
			r.Header.Set("DummyHeader", tokenString)
			goodTokenTest(mode, args, r)
		})

		It("Should return an error from an invalid token"+text, func() {
			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).ToNot(HaveOccurred())
			r.Header.Set("DummyHeader", "invalid-token")
			badTokenTest(mode, args, r)
		})

		It("Should return absent if no header is present"+text, func() {
			r, err := http.NewRequest("GET", "/", nil)
			Expect(err).ToNot(HaveOccurred())
			missingTokenTest(mode, args, r)
		})
	}
})

var _ = Describe("Bearer Token Mode", func() {
	mode, args := (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).Bearer(defaultParser)
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "Bearer "+tokenString)
		goodTokenTest(mode, args, r)
	})

	It("Should return an error from an invalid token", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "Bearer invalid-token")
		badTokenTest(mode, args, r)
	})

	It("Should return absent from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		missingTokenTest(mode, args, r)
	})
})

var _ = Describe("Basic User Token Mode", func() {
	mode, args := (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).BasicUser(defaultParser)
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth(tokenString, "")
		goodTokenTest(mode, args, r)
	})

	It("Should return an error string from an invalid token", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("invalid-token", "")
		badTokenTest(mode, args, r)
	})

	It("Should return absent from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		missingTokenTest(mode, args, r)
	})
})

var _ = Describe("Basic Password Token Mode", func() {
	mode, args := (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).BasicPassword(defaultParser)
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("", tokenString)
		goodTokenTest(mode, args, r)
	})

	It("Should return an error from an invalid token", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("", "invalid-token")
		badTokenTest(mode, args, r)
	})

	It("Should return absent from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		missingTokenTest(mode, args, r)
	})
})

var _ = Describe("TLS Terminated Robot Mode", Ordered, func() {
	var mode gotoken.TokenMode
	var args *gotoken.TokenGetterArgs
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	var invalidCert *x509.Certificate
	BeforeAll(func() {
		var err error
		cert = &x509.Certificate{
			SerialNumber: big.NewInt(int64(1000)),
			Subject: pkix.Name{
				Organization: []string{"Gotoken Unit Tests"},
				Country:      []string{"US"},
				Locality:     []string{"Cyberspace"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		Expect(err).ToNot(HaveOccurred())
		cert.Raw, err = x509.CreateCertificate(
			rand.Reader,
			cert,
			cert,
			&key.PublicKey,
			key,
		)
		Expect(err).ToNot(HaveOccurred())
		table := gotoken.MakeRobotLookupTable([]gotoken.Robot{
			{
				Name:  "test",
				Cert:  cert,
				Token: parsedToken,
			},
		})
		mode, args = (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).RobotTLSTerminated("DummyHeader", table)

		invalidCert = &x509.Certificate{
			SerialNumber: big.NewInt(int64(1001)),
			Subject: pkix.Name{
				Organization: []string{"Gotoken Unit Tests"},
				Country:      []string{"US"},
				Locality:     []string{"Cyberspace"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		invalidCert.Raw, err = x509.CreateCertificate(
			rand.Reader,
			invalidCert,
			invalidCert,
			&key.PublicKey,
			key,
		)
		Expect(err).ToNot(HaveOccurred())
	})
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		certPEM := new(bytes.Buffer)
		pem.Encode(certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		r.Header.Set("DummyHeader", url.QueryEscape(certPEM.String()))
		goodTokenTest(mode, args, r)
	})

	It("Should return an error from an unknown cert", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		certPEM := new(bytes.Buffer)
		pem.Encode(certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: invalidCert.Raw,
		})
		r.Header.Set("DummyHeader", url.QueryEscape(certPEM.String()))
		badTokenTest(mode, args, r)
	})

	It("Should return an error from an invalid token", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("DummyHeader", "invalid-cert")
		badTokenTest(mode, args, r)
	})

	It("Should return absent from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		missingTokenTest(mode, args, r)
	})
})

var _ = Describe("TLS Robot Mode", Ordered, func() {
	var mode gotoken.TokenMode
	var args *gotoken.TokenGetterArgs
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	var invalidCert *x509.Certificate
	BeforeAll(func() {
		var err error
		cert = &x509.Certificate{
			SerialNumber: big.NewInt(int64(1000)),
			Subject: pkix.Name{
				Organization: []string{"Gotoken Unit Tests"},
				Country:      []string{"US"},
				Locality:     []string{"Cyberspace"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		Expect(err).ToNot(HaveOccurred())
		cert.Raw, err = x509.CreateCertificate(
			rand.Reader,
			cert,
			cert,
			&key.PublicKey,
			key,
		)
		Expect(err).ToNot(HaveOccurred())
		table := gotoken.MakeRobotLookupTable([]gotoken.Robot{
			{
				Name:  "test",
				Cert:  cert,
				Token: parsedToken,
			},
		})
		mode, args = (&gotoken.TokenGetterArgs{}).Secure(GetTestKey).RobotTLS(table)

		invalidCert = &x509.Certificate{
			SerialNumber: big.NewInt(int64(1001)),
			Subject: pkix.Name{
				Organization: []string{"Gotoken Unit Tests"},
				Country:      []string{"US"},
				Locality:     []string{"Cyberspace"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		invalidCert.Raw, err = x509.CreateCertificate(
			rand.Reader,
			invalidCert,
			invalidCert,
			&key.PublicKey,
			key,
		)
		Expect(err).ToNot(HaveOccurred())
	})
	It("Should extract a token from a valid session", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
		goodTokenTest(mode, args, r)
	})

	It("Should return an error from an unknown cert", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{invalidCert},
		}
		badTokenTest(mode, args, r)
	})

	It("Should return an error from a non-tls session", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		errorTokenTest(mode, args, r)
	})

	It("Should return absent from a missing cert", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.TLS = &tls.ConnectionState{}
		missingTokenTest(mode, args, r)
	})

})

var _ = Describe("Symmetric Robot", func() {
	table := gotoken.MakeSymmetricRobotLookupTable([]gotoken.SymmetricRobot{
		{
			Name:        "test",
			SecretToken: symmetricTokenString,
			Token:       parsedToken,
		},
	})
	It("Should return a token from a valid secret", func() {
		mode, args := (&gotoken.TokenGetterArgs{}).SymmetricRobot(table, func(*http.Request) string { return symmetricTokenString })
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		goodTokenTest(mode, args, r)
	})
	It("Should return absent from a missing secret", func() {
		mode, args := (&gotoken.TokenGetterArgs{}).SymmetricRobot(table, func(*http.Request) string { return "" })
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		missingTokenTest(mode, args, r)
	})
	It("Should return error from an unknown secret", func() {
		mode, args := (&gotoken.TokenGetterArgs{}).SymmetricRobot(table, func(*http.Request) string { return "garbage" })
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(mode, args, r)
	})
})
