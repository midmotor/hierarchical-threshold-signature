package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type schnorr struct {
	value          curves.Point
	challenge      [32]byte
	randomexponent curves.Point
	proof          curves.Scalar
}

func (s *schnorr) Create(value curves.Point, secret curves.Scalar, curvetype string) (*schnorr, error) {
	s.value = value
	curve := getCurve(curvetype)
	k := curve.Scalar.Random(rand.Reader)

	if k.IsZero() {
		return nil, errors.New("random number could not be 0")
	}

	//k*G
	K := curve.Point.Generator().Mul(k)
	s.randomexponent = K
	//c = hash(value, randomexpo, G)
	c := append(s.value.ToAffineCompressed()[:], s.randomexponent.ToAffineCompressed()[:]...)
	c = append(c, curve.Point.Generator().ToAffineCompressed()...)
	s.challenge = sha256.Sum256(c)
	challengescalar := curve.Scalar.Hash(bytehelper.ArrayToSlice(s.challenge))
	//proof = k-s*c
	s.proof = k.Sub(secret.Mul(challengescalar))

	return s, nil
}

func (s schnorr) Verify(curvetype string) error {
	curve := getCurve(curvetype)
	c := append(s.value.ToAffineCompressed()[:], s.randomexponent.ToAffineCompressed()[:]...)
	c = append(c, curve.Point.Generator().ToAffineCompressed()...)
	challenge := sha256.Sum256(c)

	if s.challenge != challenge {
		return errors.New("challenge values did not match.")
	}

	challengescalar := curve.Scalar.Hash(bytehelper.ArrayToSlice(challenge))

	// proof.G + (s*c).G =? k.G
	if curve.Point.Generator().Mul(s.proof).Add(s.value.Mul(challengescalar)).Equal(s.randomexponent) {
		return nil
	} else {
		return errors.New("schnorr proof could not be proved")
	}

}
