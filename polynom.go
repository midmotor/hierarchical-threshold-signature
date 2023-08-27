package frost

import (
	"crypto/rand"
	"strings"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

const P256 string = "P256"
const K256 string = "K256"
const ED25519 string = "25519"

type Polynomial struct {
	Coefficients []curves.Scalar
	threshold    int
}

// for curve.Point.Generator()
func getCurve(s string) *curves.Curve {

	s = strings.ToLower((s))

	if strings.Contains(s, P256) {
		return curves.P256()
	} else if strings.Contains(s, K256) {
		return curves.K256()
	} else if strings.Contains(s, ED25519) {
		return curves.ED25519()
	}
	return curves.K256()
}

// creates d degree polynomial
func (p *Polynomial) Init(threshold int, curvetype string) *Polynomial {
	curve := getCurve(curvetype)
	p.threshold = threshold
	p.Coefficients = make([]curves.Scalar, threshold)
	for i := 0; i < threshold; i++ {
		p.Coefficients[i] = curve.Scalar.Random(rand.Reader)
	}

	return p
}

// calculates p(x)
func (p Polynomial) Evaluate(x curves.Scalar) curves.Scalar {
	// Horner method
	out := p.Coefficients[p.threshold-1].Clone()

	for i := p.threshold - 2; i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}

	return out
}

// pedersen commitment, commit() = a_0.G + a_1.G + a_2.G + ...
func (p Polynomial) Commit(curvetype string) []curves.Point {
	polycommit := make([]curves.Point, p.threshold)
	curve := curves.GetCurveByName(p.Coefficients[0].Point().Generator().CurveName())

	for i := 0; i < int(p.threshold); i++ {
		// polycommit_i = a_i*G
		polycommit[i] = (curve.Point.Generator().Mul(p.Coefficients[i]))
	}

	return polycommit
}

// calculate p(list[i]) where list is index of participants.
func (p Polynomial) EvaluateSecret(ppoly []curves.Scalar, m int, curvetype string) []curves.Scalar {
	polyouts := make([]curves.Scalar, m)
	curve := getCurve(curvetype)
	for i := 0; i < m; i++ {
		polyouts[i] = p.Evaluate(curve.Scalar.New(i + 1)).Clone()
	}

	return polyouts
}
