package gotoken_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGotoken(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gotoken Suite")
}
