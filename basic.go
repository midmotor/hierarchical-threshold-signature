package frost

import (
	"errors"
	"math"

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

func derivative(coefficients []curves.Scalar, curvetype string) []curves.Scalar {
	curve := getCurve(curvetype)
	degree := len(coefficients) - 1
	derivativeCoefficients := make([]curves.Scalar, degree)

	for i := 1; i <= degree; i++ {
		derivativeCoefficients[i-1] = coefficients[i].Mul(curve.Scalar.New(i))
	}

	return derivativeCoefficients
}

// for tassa commit
func derivcommit(com []curves.Point, curvetype string) []curves.Point {
	curve := getCurve(curvetype)
	newthresh := len(com) - 1
	newcom := make([]curves.Point, newthresh)

	for i := 0; i < newthresh; i++ {
		newcom[i] = com[i+1].Mul(curve.Scalar.New(i + 1))

	}

	return newcom

}

// 1 boss whose is index 1, other is emplo.
func tassacoeff(t int, curvetype string) [][]curves.Scalar {
	curve := getCurve(curvetype)
	matrix := make([][]curves.Scalar, t)

	for i := range matrix {
		matrix[i] = make([]curves.Scalar, t)
	}

	firstrow := make([]curves.Scalar, t)

	for i := 0; i < t; i++ {
		firstrow[i] = curve.Scalar.New(1)

	}
	matrix[0] = firstrow

	for i := 0; i < t; i++ {
		firstrow[i] = curve.Scalar.New(1)

	}

	for i := 1; i < t; i++ {
		for j := 0; j < t; j++ {
			if j == 0 {
				matrix[i][j] = curve.Scalar.Zero()
			} else if j == 1 {
				matrix[i][j] = curve.Scalar.New(1)
			} else {
				matrix[i][j] = curve.Scalar.New(j).Mul(curve.Scalar.New(int(math.Pow(float64(i+1), float64(j-1)))))
			}
		}
	}

	return matrix
}
