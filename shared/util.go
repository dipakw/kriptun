package shared

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func Rand(size int) ([]byte, error) {
	buf := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func Hamc(a []byte, b []byte) ([]byte, error) {
	h := hmac.New(sha256.New, a)

	if _, err := h.Write(b); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
