package frost

import (
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

type Sharing struct {
	threshold int
	keys      []curves.Scalar
	IDlist    []curves.Scalar
}

// shares the secret
func (share *Sharing) Init(t int, list []curves.Scalar, poly Polynomial) *Sharing {

	share.threshold = t
	share.IDlist = list
	share.keys = make([]curves.Scalar, len(share.IDlist))

	for i := 0; i < len(share.IDlist); i++ {
		share.keys[i] = poly.Evaluate(list[i]).Clone()
	}

	return share
}
func Sscheck(ownerID curves.Scalar, sskey curves.Scalar, com []curves.Point, t int) error {
	if t != len(com) {
		return errors.New("the length of commitment is not equal to threshold")
	}

	curve := curves.GetCurveByName(com[0].CurveName())
	exponent := make([]curves.Scalar, t)
	exponent[0] = curve.Scalar.One().Clone()
	temp := ownerID
	// exp[0] := 1, exp[1] := ID, exp[2] := ID^2, .........
	for i := 1; i < int(t); i++ {
		exponent[i] = temp
		temp = temp.Mul(temp)
	}

	out := com[0]
	for i := 1; i < int(t); i++ {
		//a_0*G  + a_1.x*G + a_2.x^2*G + .......
		out = out.Add(com[i].Mul(exponent[i]))
	}

	if curve.Point.Generator().Mul(sskey).Equal(out) {
		return nil
	} else {
		return errors.New("the secret value sent by the participant and the commitment values did not match.")
	}
}
