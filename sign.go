package frost

import (
	"crypto/rand"
	"crypto/sha256"

	"strconv"

	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type preprocess struct {
	nonce       []curves.Scalar
	noncecommit []curves.Point
}

func (pre *preprocess) Init(curvetype string) *preprocess {
	curve := getCurve(curvetype)
	nonce := make([]curves.Scalar, 2)
	noncecommit := make([]curves.Point, 2)

	nonce[0] = curve.Scalar.Random(rand.Reader)
	nonce[1] = curve.Scalar.Random(rand.Reader)

	noncecommit[0] = curve.Point.Generator().Mul(nonce[0])
	noncecommit[1] = curve.Point.Generator().Mul(nonce[1])

	pre.nonce = nonce
	pre.noncecommit = noncecommit

	return pre
}

func hash1(message string, l int, nonces []curves.Point, curvetype string) curves.Scalar {

	curve := getCurve(curvetype)
	// hash(l, message, nonces)
	lbyte := []byte(strconv.Itoa(l))
	m := []byte(message)
	pre := append(m, lbyte...)
	for i := 0; i < len(nonces); i++ {
		pre = append(pre, nonces[i].ToAffineCompressed()...)
	}

	prero := sha256.Sum256(pre)

	ro := curve.Scalar.Hash(bytehelper.ArrayToSlice(prero))

	return ro

}

func hash2(groupcom curves.Point, grouppub curves.Point, message string, curvetype string) curves.Scalar {

	curve := getCurve(curvetype)
	// hash(R, Y, message)
	groupcombyte := groupcom.ToAffineCompressed()
	grouppubbyte := grouppub.ToAffineCompressed()
	m := []byte(message)
	prec := append(groupcombyte, grouppubbyte...)
	prec = append(prec, m...)

	hashc := sha256.Sum256(prec)

	c := curve.Scalar.Hash(bytehelper.ArrayToSlice(hashc))

	return c

}

func groupcommit(ro []curves.Scalar, nonces []curves.Point, curvetype string) curves.Point {
	curve := getCurve(curvetype)
	R := curve.Point.Identity()
	for i := 0; i < (len(nonces) / 2); i++ {
		R = R.Add(nonces[2*i].Add(nonces[2*i+1].Mul(ro[i])))
	}

	return R

}
