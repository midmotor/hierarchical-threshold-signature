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
