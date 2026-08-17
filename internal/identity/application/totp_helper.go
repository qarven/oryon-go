package application

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/qarven/oryon-go/internal/identity/domain"
)

func generateTOTPSecret(length int) ([]byte, error) {
	if length <= 0 {
		length = 20
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func base32EncodeNoPadding(src []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(src)
}

func base32DecodeNoPadding(s string) ([]byte, error) {
	// add padding if needed, handle case-insensitive
	s = strings.ToUpper(s)
	s = strings.TrimSpace(s)

	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	// also try StdEncoding with padding fallback
	b, err := enc.DecodeString(s)
	if err != nil {
		// try with padding
		if mod := len(s) % 8; mod != 0 {
			s += strings.Repeat("=", 8-mod)
		}

		b, err = base32.StdEncoding.DecodeString(s)
	}

	return b, err
}

func totpHashFunc(algo domain.TotpAlgorithm) (func() hash.Hash, error) {
	switch algo {
	case domain.TotpAlgorithmSHA1:
		return sha1.New, nil
	case domain.TotpAlgorithmSHA256:
		return sha256.New, nil
	case domain.TotpAlgorithmSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
}

func totpCode(secret []byte, algo domain.TotpAlgorithm, digits int, period int, t time.Time) (string, error) {
	hf, err := totpHashFunc(algo)
	if err != nil {
		return "", err
	}

	counter := uint64(t.Unix() / int64(period))
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(hf, secret)
	_, _ = mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	offset := int(sum[len(sum)-1] & 0x0f)
	if offset+4 > len(sum) {
		return "", fmt.Errorf("invalid offset")
	}

	binCode := binary.BigEndian.Uint32(sum[offset : offset+4])
	binCode &= 0x7fffffff

	pow := int(math.Pow10(digits))
	code := binCode % uint32(pow)

	format := fmt.Sprintf("%%0%dd", digits)

	return fmt.Sprintf(format, code), nil
}

func validateTOTP(secret []byte, code string, algo domain.TotpAlgorithm, digits, period, skew int, now time.Time) bool {
	if skew < 0 {
		skew = 0
	}

	for i := -skew; i <= skew; i++ {
		t := now.Add(time.Duration(i*period) * time.Second)
		expected, err := totpCode(secret, algo, digits, period, t)
		if err != nil {
			continue
		}

		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}

	return false
}

func buildOTPAuthURI(issuer, account string, secret string, algo domain.TotpAlgorithm, digits, period int) string {
	var algoStr string
	switch algo {
	case domain.TotpAlgorithmSHA1:
		algoStr = "SHA1"
	case domain.TotpAlgorithmSHA256:
		algoStr = "SHA256"
	case domain.TotpAlgorithmSHA512:
		algoStr = "SHA512"
	default:
		algoStr = "SHA1"
	}

	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, account))
	if issuer == "" {
		label = url.PathEscape(account)
	}

	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", algoStr)
	params.Set("digits", fmt.Sprintf("%d", digits))
	params.Set("period", fmt.Sprintf("%d", period))

	return fmt.Sprintf("otpauth://totp/%s?%s", label, params.Encode())
}
