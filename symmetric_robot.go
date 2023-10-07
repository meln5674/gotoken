package gotoken

import (
	"github.com/golang-jwt/jwt/v4"
)

// A SymmetricRobot is like a Robot, but uses an opaque symmetric value (which must be kept secret)
// to map to the JWT instead of an mTLS certificate.
// Because the secret token must be kept secret, and can be used to impersonate the robot, SymmetricRobots
// should only be used when the robot operator is willing to accept that risk, or when the app operator
// and robot operator are one in the same
type SymmetricRobot struct {
	Name        string
	SecretToken string
	Token       *jwt.Token
}

type SymmetricRobotLookupTable map[string]SymmetricRobot

func (s SymmetricRobotLookupTable) Lookup(secretToken string) (SymmetricRobot, bool) {
	robot, ok := s[secretToken]
	return robot, ok
}

// MakeSymmetricRobotLookupTables takes a set of robots and produces an O(1) lookup table mapping their certificates to their JWTs
func MakeSymmetricRobotLookupTable(robots []SymmetricRobot) SymmetricRobotLookupTable {
	robotsBySecret := make(map[string]SymmetricRobot, len(robots))
	for _, robot := range robots {
		robotsBySecret[robot.SecretToken] = robot
	}
	return SymmetricRobotLookupTable(robotsBySecret)
}
