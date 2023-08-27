package frost

import (
	"errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func equality(lhs curves.Scalar, rhs curves.Scalar) error {
	if lhs.Cmp(rhs) == 0 {
		return nil
	} else {
		return errors.New("values are not equal")

	}
}

func lagrangecoefficient(thresholdIDlist []curves.Scalar, value curves.Scalar, curvetype string) []curves.Scalar {
	n := len(thresholdIDlist)
	lagranges := make([]curves.Scalar, n)
	curve := getCurve(curvetype)

	for i := 0; i < n; i++ {
		temp := curve.Scalar.One().Clone()
		for j := 0; j < n; j++ {
			if j != i {
				temp = temp.Mul((value.Sub(thresholdIDlist[j])).Div(thresholdIDlist[i].Sub(thresholdIDlist[j])))

			}
		}
		lagranges[i] = temp.Clone()
	}

	return lagranges
}

func scalarexponent(t int, id curves.Scalar, curvetype string) []curves.Scalar {
	curve := getCurve(curvetype)
	exponent := make([]curves.Scalar, t)

	exponent[0] = curve.Scalar.One().Clone()
	temp := id
	for i := 1; i < t; i++ {
		exponent[i] = temp
		temp = temp.Mul(temp)
	}

	return exponent
}

func secretcheck(id curves.Scalar, sskey curves.Scalar, com []curves.Point, t int) error {
	if t != len(com) {
		return errors.New("the length of commitment is not equal to threshold")
	}

	curve := getCurve(com[0].CurveName())
	exponent := make([]curves.Scalar, t)
	exponent[0] = curve.Scalar.One().Clone()
	temp := id
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
