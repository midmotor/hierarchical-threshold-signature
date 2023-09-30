package frost

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type keygenr1 struct {
	poly   Polynomial
	sch    schnorr
	commit []curves.Point
}

func (keyr1 keygenr1) Init(threshold int, curvetype string) keygenr1 {
	keyr1.poly = *new(Polynomial).Init(threshold, curvetype)
	keyr1.commit = keyr1.poly.Commit(curvetype)
	sch, _ := new(schnorr).Create(keyr1.commit[0], keyr1.poly.Coefficients[0], curvetype)
	keyr1.sch = *sch

	return keyr1
}

type keygenr2 struct {
	secrets []curves.Scalar
}

func (keyr2 keygenr2) Init(m int, keyr1 keygenr1, curvetype string) keygenr2 {
	keyr2.secrets = keyr1.poly.EvaluateSecret(keyr1.poly.Coefficients, m, curvetype)

	return keyr2
}

// just for one boss whose index is 1
func (tasskeyr2 keygenr2) TassaInit(m int, keyr1 keygenr1, curvetype string) keygenr2 {
	curve := getCurve(curvetype)
	tasskeyr2.secrets = make([]curves.Scalar, m)
	tasskeyr2.secrets[0] = keyr1.poly.Evaluate(curve.Scalar.New(1))

	dpoly := derivative(keyr1.poly.Coefficients, curvetype)
	temppoly := new(Polynomial).Init(keyr1.poly.threshold-1, curvetype)

	for i := 0; i < len(dpoly); i++ {
		temppoly.Coefficients[i] = dpoly[i]
	}
	for i := 1; i < m; i++ {
		tasskeyr2.secrets[i] = temppoly.Evaluate(curve.Scalar.New(i + 1)).Clone()
	}

	return tasskeyr2
}
