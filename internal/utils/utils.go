package utils

import (
	"crypto/md5"
	"encoding/hex"
	"github.com/OmniTrustILM/ct-logs-discovery-provider/internal/logger"

	"github.com/google/uuid"
)

var log = logger.Get()

func GenerateRandomUUID() string {
	uuid, err := uuid.NewRandom()
	if err != nil {
		log.Error(err.Error())
	}
	return uuid.String()
}

func DeterministicGUID(parts ...string) string {
	// concatenate all strings
	var combined string
	for _, part := range parts {
		combined += part
	}

	md5hash := md5.New()
	md5hash.Write([]byte(combined))

	// convert the hash value to a string
	md5string := hex.EncodeToString(md5hash.Sum(nil))

	// generate the UUID from the
	// first 16 bytes of the MD5 hash
	uuidByte, err := uuid.FromBytes([]byte(md5string[0:16]))
	if err != nil {
		log.Error(err.Error())
	}

	return uuidByte.String()
}
