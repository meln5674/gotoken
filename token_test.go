package gotoken_test

import (
	"net/http"

	"github.com/meln5674/gotoken"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func goodTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	Expect(getter(req)).To(Equal("token-value"))
}

func badTokenTest(mode string, args *gotoken.TokenGetterArgs, req *http.Request) {
	GinkgoHelper()
	getter, ok := gotoken.GetTokenGetter(mode, args)
	Expect(ok).To(BeTrue())
	Expect(getter(req)).To(BeEmpty())
}

var _ = Describe("Raw Token Mode", func() {
	It("Should extract a token from a matching header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("DummyHeader", "token-value")
		goodTokenTest(gotoken.TokenModeRaw, &gotoken.TokenGetterArgs{HeaderName: "DummyHeader"}, r)
	})

	It("Should return an empty string if no header is present", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(gotoken.TokenModeRaw, &gotoken.TokenGetterArgs{HeaderName: "DummyHeader"}, r)
	})
})

var _ = Describe("Bearer Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "Bearer token-value")
		goodTokenTest(gotoken.TokenModeBearer, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(gotoken.TokenModeBearer, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(gotoken.TokenModeBearer, &gotoken.TokenGetterArgs{}, r)
	})
})

var _ = Describe("Basic User Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("token-value", "")
		goodTokenTest(gotoken.TokenModeBasicUser, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(gotoken.TokenModeBasicUser, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(gotoken.TokenModeBasicUser, &gotoken.TokenGetterArgs{}, r)
	})
})

var _ = Describe("Basic Password Token Mode", func() {
	It("Should extract a token from a valid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.SetBasicAuth("", "token-value")
		goodTokenTest(gotoken.TokenModeBasicPassword, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from an invalid header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		r.Header.Set("Authorization", "some-nonsense token-value")
		badTokenTest(gotoken.TokenModeBasicPassword, &gotoken.TokenGetterArgs{}, r)
	})

	It("Should return empty string from a missing header", func() {
		r, err := http.NewRequest("GET", "/", nil)
		Expect(err).ToNot(HaveOccurred())
		badTokenTest(gotoken.TokenModeBasicPassword, &gotoken.TokenGetterArgs{}, r)
	})
})
