package campid

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/influx6/npkg/nerror"
	"github.com/influx6/npkg/nunsafe"
	"github.com/oklog/ulid/v2"
)

// UlidReader provides a safe entropy to be used in concurrent tasks.
// https://github.com/oklog/ulid/blob/0d4fda9d6345755e157a256fd33d48556c5f4a7a/ulid_test.go#L633-L636
type UlidReader struct {
	mtx sync.Mutex
	ulid.MonotonicReader
}

// New returns a new MonotonicReader.
func NewUlidReader() *UlidReader {
	monotonic := ulid.Monotonic(rand.New(
		rand.NewSource(time.Now().UnixNano()),
	), 0)

	return &UlidReader{MonotonicReader: monotonic}
}

func (r *UlidReader) NextString(length int) (string, error) {
	return r.MonotonicString(uint64(time.Now().Unix()), length)
}

func (r *UlidReader) MonotonicString(timeInUnix uint64, length int) (string, error) {
	var targetBytes = make([]byte, length)
	var generatedErr = r.MonotonicRead(timeInUnix, targetBytes)
	if generatedErr != nil {
		return "", nerror.WrapOnly(generatedErr)
	}
	return nunsafe.Bytes2String(targetBytes), nil
}

func (r *UlidReader) MonotonicRead(timeInUnix uint64, p []byte) (err error) {
	r.mtx.Lock()
	err = r.MonotonicReader.MonotonicRead(timeInUnix, p)
	r.mtx.Unlock()

	return err
}

// Bytes returns securely generated random bytes.
func Bytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := crand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// BytesFromSample returns securely generated random bytes from a string
// sample.
func BytesFromSample(length int, samples ...string) ([]byte, error) {
	sample := strings.Join(samples, "")
	if sample == "" {
		sample = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
			"[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	}

	bytes, err := Bytes(length)
	if err != nil {
		return nil, err
	}
	for i, b := range bytes {
		bytes[i] = sample[b%byte(len(sample))]
	}

	return bytes, nil
}

// String returns a securely generated random string from an optional
// sample.
func String(length int, samples ...string) (string, error) {
	b, err := BytesFromSample(length, samples...)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// StringB64 returns a securely generated random string from an optional
// sample, encoded in base64.
func StringB64(length int, samples ...string) (string, error) {
	b, err := BytesFromSample(length, samples...)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Hash returns a sha512 hash of a string.
func Hash(s string) (string, error) {
	h := sha512.New()
	_, err := h.Write([]byte(s))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
