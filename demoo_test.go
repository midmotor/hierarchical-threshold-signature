package frost

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestPlainFROST(t *testing.T) {
	// Plain FROST t=3 m=4

	//KeyGen Round1
	thresh := 3
	number := 4
	curvetype := "25519"
	curve := getCurve(curvetype)

	//FROST Keygen Round1.1-2-3
	p1keyr1 := new(keygenr1).Init(thresh, curvetype)
	p2keyr1 := new(keygenr1).Init(thresh, curvetype)
	p3keyr1 := new(keygenr1).Init(thresh, curvetype)
	p4keyr1 := new(keygenr1).Init(thresh, curvetype)

	//FROST Keygen Round1.5
	for i := 0; i < (number - 1); i++ {
		p1keyr1.sch.Verify(curvetype)
		//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
		p2keyr1.sch.Verify(curvetype)
		p3keyr1.sch.Verify(curvetype)
		p4keyr1.sch.Verify(curvetype)
	}

	//KeyGen Round2
	p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
	p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
	p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
	p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
	/*
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4keyr1.commit, thresh)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4keyr1.commit, thresh)

		// participant4 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4keyr1.commit, thresh)
	*/

	//Participants check the secrets value FROST Keygen Round2.2
	for i := 0; i < number; i++ {
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
	}

	// add secrets and calculate sharing keys FROST Keygen Round2.3
	p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0])
	p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1])
	p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2])
	p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3])

	// calculates participants public key FROST Keygen Round2.4
	p1pub := curve.Point.Generator().Mul(p1secret)
	p2pub := curve.Point.Generator().Mul(p2secret)
	p3pub := curve.Point.Generator().Mul(p3secret)
	p4pub := curve.Point.Generator().Mul(p4secret)

	_ = p4pub
	// calculates group's public key FROST Keygen Round2.4
	grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0])

	list := make([]curves.Scalar, 3)
	list[0] = curve.Scalar.New(1)
	list[1] = curve.Scalar.New(2)
	list[2] = curve.Scalar.New(3)
	lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

	// check!
	fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))

	//FROST Preprocess. For simplicity, use 1 nonce
	p1pre := new(preprocess).Init(curvetype)
	p2pre := new(preprocess).Init(curvetype)
	p3pre := new(preprocess).Init(curvetype)
	p4pre := new(preprocess).Init(curvetype)
	_ = p4pre

	//Frost Sign (participant1, participant2 and participant3 join the sign phase)

	message := "Hierarchical Threshold Sign"

	nonces := make([]curves.Point, 2*thresh)
	nonces[0] = p1pre.noncecommit[0]
	nonces[1] = p1pre.noncecommit[1]
	nonces[2] = p2pre.noncecommit[0]
	nonces[3] = p2pre.noncecommit[1]
	nonces[4] = p3pre.noncecommit[0]
	nonces[5] = p3pre.noncecommit[1]

	// ro = hash(l,m,B)
	ro1 := hash1(message, 1, nonces, curvetype)
	ro2 := hash1(message, 2, nonces, curvetype)
	ro3 := hash1(message, 3, nonces, curvetype)

	ro := make([]curves.Scalar, 3)
	ro[0] = ro1
	ro[1] = ro2
	ro[2] = ro3

	// each Participant derives group commitment
	R := groupcommit(ro, nonces, curvetype)

	// c = hash(R,Y,m)
	c := hash2(R, grouppub, message, curvetype)

	// each Participant computes their sign
	p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
	p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
	p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))

	// Sign Aggregator SA performs following

	ro1 = hash1(message, 1, nonces, curvetype)
	ro2 = hash1(message, 2, nonces, curvetype)
	ro3 = hash1(message, 3, nonces, curvetype)

	// R_i = D_i + ro_iE_i
	R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
	R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
	R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))

	// bigR = R_1 + R_2 + R_3
	saR := R1.Add(R2).Add(R3)
	sac := hash2(saR, grouppub, message, curvetype)
	// fmt.Printf("%t", R.Equal(saR))

	//check pisign.G =? R_i + (c*lagrangei)Y_i
	fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
	fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
	fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2])))))

	// compute sign

	sign := p1sign.Add(p2sign).Add(p3sign)

	_ = sign
}

func TestOurSchemeFROST(t *testing.T) {
	// Hierarc. FROST (1,1) (2,3)

	// Level1 Keygen

	curvetype := "25519"
	curve := getCurve(curvetype)
	l1secret := curve.Scalar.Random(rand.Reader)
	l1pub := curve.Point.Generator().Mul(l1secret)

	// Level2 Keygen

	thresh := 2
	number := 3

	l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
	l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
	l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)

	for i := 0; i < (number - 1); i++ {
		l2n1keyr1.sch.Verify(curvetype)
		//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
		l2n2keyr1.sch.Verify(curvetype)
		l2n3keyr1.sch.Verify(curvetype)

	}

	//KeyGen Round2
	l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
	l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
	l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)

	for i := 0; i < number; i++ {
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
		fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
	}

	// add secrets and calculate sharing keys
	l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0])
	l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1])
	l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2])

	// calculates level2nodes public key
	l2n1pub := curve.Point.Generator().Mul(l2n1secret)
	l2n2pub := curve.Point.Generator().Mul(l2n2secret)
	l2n3pub := curve.Point.Generator().Mul(l2n3secret)

	_ = l2n3pub

	l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0])

	//Key Aggeregation

	// level1 node1.1 proofgen
	l1sch, _ := new(schnorr).Create(l1pub, l1secret, curvetype)

	// level2 nodes proofverify
	for i := 0; i < number; i++ {
		l1sch.Verify(curvetype)
	}

	// ym = y1 + y2
	masterpub := l1pub.Add(l2pub)
	_ = masterpub

	//preprocessing level1 and level2
	l1pre := new(preprocess).Init(curvetype)
	l2n1pre := new(preprocess).Init(curvetype)
	l2n2pre := new(preprocess).Init(curvetype)
	l2n3pre := new(preprocess).Init(curvetype)
	_ = l2n3pre

	//Sign (node1.1 node2.1 and node2.2 join the sign phase)
	message := "Hierarchical Threshold Sign"

	nonces := make([]curves.Point, 2*(thresh+1))
	nonces[0] = l1pre.noncecommit[0]
	nonces[1] = l1pre.noncecommit[1]
	nonces[2] = l2n1pre.noncecommit[0]
	nonces[3] = l2n1pre.noncecommit[1]
	nonces[4] = l2n2pre.noncecommit[0]
	nonces[5] = l2n2pre.noncecommit[1]

	// ro = hash(l,m,B)
	ro1 := hash1(message, 1, nonces, curvetype)
	ro2 := hash1(message, 2, nonces, curvetype)
	ro3 := hash1(message, 3, nonces, curvetype)

	ro := make([]curves.Scalar, 3)
	ro[0] = ro1
	ro[1] = ro2
	ro[2] = ro3

	// each Participant derives group commitment
	R := groupcommit(ro, nonces, curvetype)

	// c = hash(R,Y,m)
	c := hash2(R, masterpub, message, curvetype)

	// level1 sign
	l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

	// level2 signs
	list := make([]curves.Scalar, 2)
	list[0] = curve.Scalar.New(1)
	list[1] = curve.Scalar.New(2)
	lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

	l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
	l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))

	// Sign Aggregator SA performs following

	ro1 = hash1(message, 1, nonces, curvetype)
	ro2 = hash1(message, 2, nonces, curvetype)
	ro3 = hash1(message, 3, nonces, curvetype)

	// R_i = D_i + ro_iE_i
	R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
	R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
	R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))

	// bigR = R_1 + R_2 + R_3
	saR := R1.Add(R2).Add(R3)
	sac := hash2(saR, masterpub, message, curvetype)
	//fmt.Printf("%t", R.Equal(saR))
	//fmt.Printf("%t", equality(sac, c))

	//check pisign.G =? R_i + (c*lagrangei)Y_i
	fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
	fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
	fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))

	sign := l1sign.Add(l2n1sign).Add(l2n2sign)

	_ = sign

}
