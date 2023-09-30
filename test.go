package frost

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

//	start := time.Now()
//	for i := 0; i < 1000; i++ {
//		duration := time.Since(start) fmt.Println("t3 m4 Tassa 25519", duration/1000)

func TestTassaFROSTt3m4(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()

	//KeyGen Round1
	thresh := 3
	number := 4
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {

		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)

		pubs := make([]curves.Point, 4)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0])

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
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))

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
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Tassa 25519", duration/1000)

}
func TestPlainFROSTt3m4(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 3
	number := 4
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
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
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub)

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
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Plain 25519", duration/1000)

}

func TestOurSchemeFROSTt3m4(t *testing.T) {
	// Hierarc. FROST (1,1) (2,3)
	start := time.Now()
	// Level1 Keygen

	curvetype := "25519"
	curve := getCurve(curvetype)
	thresh := 2
	number := 3

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

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

		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
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

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Our 25519", duration/1000)

}

func TestTassaFROSTt4m5(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 5
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		_ = p5pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m5 Tassa 25519", duration/1000)
}

func TestPlainFROSTt4m5(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 5
	curvetype := "25519"
	curve := getCurve(curvetype)
	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)

		_ = p5pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0])

		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		_ = p5pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}

	duration := time.Since(start)
	fmt.Println("t4 m5 Plain 25519", duration/1000)
}

func TestOurSchemeFROSTt4m5(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "25519"
	curve := getCurve(curvetype)
	thresh := 3
	number := 4

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)

		_ = l2n4pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		_ = l2n4pre

		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}

	duration := time.Since(start)
	fmt.Println("t4 m5 Our 25519", duration/1000)
}

func TestTassaFROSTt4m7(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 7
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).TassaInit(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).TassaInit(number, p7keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)
		p6derivcommit := derivcommit(p6keyr1.commit, curvetype)
		p7derivcommit := derivcommit(p7keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p6keyr2.secrets[0], p6keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p7keyr2.secrets[0], p7keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p6keyr2.secrets[1], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p7keyr2.secrets[1], p7derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p6keyr2.secrets[2], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p7keyr2.secrets[2], p7derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p6keyr2.secrets[3], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p7keyr2.secrets[3], p7derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p6keyr2.secrets[4], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p7keyr2.secrets[4], p7derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(6), p1keyr2.secrets[5], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p2keyr2.secrets[5], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p3keyr2.secrets[5], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p4keyr2.secrets[5], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p5keyr2.secrets[5], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p6keyr2.secrets[5], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p7keyr2.secrets[5], p7derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(7), p1keyr2.secrets[6], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p2keyr2.secrets[6], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p3keyr2.secrets[6], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p4keyr2.secrets[6], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p5keyr2.secrets[6], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p6keyr2.secrets[6], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p7keyr2.secrets[6], p7derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub
		pubs[5] = p6pub
		pubs[6] = p7pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)

		_ = p5pre
		_ = p6pre
		_ = p7pre

		//Frost Sign (participant1, participant2 and participant3 and participant4 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Tassa 25519", duration/1000)
}

func TestPlainFROSTt4m7(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 7
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).Init(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).Init(number, p7keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p6keyr2.secrets[i], p6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p7keyr2.secrets[i], p7keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)

		_ = p5pub
		_ = p6pub
		_ = p7pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0])

		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		_ = p5pre
		_ = p6pre
		_ = p7pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Plain 25519", duration/1000)
}

func TestOurSchemeFROSTt4m7(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "25519"
	curve := getCurve(curvetype)
	thresh := 3
	number := 7
	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n5keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n6keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)
			l2n5keyr1.sch.Verify(curvetype)
			l2n6keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		l2n5keyr2 := new(keygenr2).Init(number, l2n5keyr1, curvetype)
		l2n6keyr2 := new(keygenr2).Init(number, l2n6keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n5keyr2.secrets[i], l2n5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n6keyr2.secrets[i], l2n6keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0]).Add(l2n5keyr2.secrets[0]).Add(l2n6keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1]).Add(l2n5keyr2.secrets[1]).Add(l2n6keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2]).Add(l2n5keyr2.secrets[2]).Add(l2n6keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3]).Add(l2n5keyr2.secrets[3]).Add(l2n6keyr2.secrets[3])
		l2n5secret := l2n1keyr2.secrets[4].Add(l2n2keyr2.secrets[4]).Add(l2n3keyr2.secrets[4]).Add(l2n4keyr2.secrets[4]).Add(l2n5keyr2.secrets[4]).Add(l2n6keyr2.secrets[4])
		l2n6secret := l2n1keyr2.secrets[5].Add(l2n2keyr2.secrets[5]).Add(l2n3keyr2.secrets[5]).Add(l2n4keyr2.secrets[5]).Add(l2n5keyr2.secrets[5]).Add(l2n6keyr2.secrets[5])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)
		l2n5pub := curve.Point.Generator().Mul(l2n5secret)
		l2n6pub := curve.Point.Generator().Mul(l2n6secret)

		_ = l2n4pub
		_ = l2n5pub
		_ = l2n6pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0]).Add(l2n5keyr1.commit[0]).Add(l2n6keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		l2n5pre := new(preprocess).Init(curvetype)
		l2n6pre := new(preprocess).Init(curvetype)

		_ = l2n4pre
		_ = l2n5pre
		_ = l2n6pre
		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Our 25519", duration/1000)

}

func TestTassaFROSTt4m10(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 10
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)
		p8keyr1 := new(keygenr1).Init(thresh, curvetype)
		p9keyr1 := new(keygenr1).Init(thresh, curvetype)
		p10keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
			p8keyr1.sch.Verify(curvetype)
			p9keyr1.sch.Verify(curvetype)
			p10keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).TassaInit(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).TassaInit(number, p7keyr1, curvetype)
		p8keyr2 := new(keygenr2).TassaInit(number, p8keyr1, curvetype)
		p9keyr2 := new(keygenr2).TassaInit(number, p9keyr1, curvetype)
		p10keyr2 := new(keygenr2).TassaInit(number, p10keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)
		p6derivcommit := derivcommit(p6keyr1.commit, curvetype)
		p7derivcommit := derivcommit(p7keyr1.commit, curvetype)
		p8derivcommit := derivcommit(p8keyr1.commit, curvetype)
		p9derivcommit := derivcommit(p9keyr1.commit, curvetype)
		p10derivcommit := derivcommit(p10keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p6keyr2.secrets[0], p6keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p7keyr2.secrets[0], p7keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p8keyr2.secrets[0], p8keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p9keyr2.secrets[0], p9keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p10keyr2.secrets[0], p10keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p6keyr2.secrets[1], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p7keyr2.secrets[1], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p8keyr2.secrets[1], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p9keyr2.secrets[1], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p10keyr2.secrets[1], p10derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p6keyr2.secrets[2], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p7keyr2.secrets[2], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p8keyr2.secrets[2], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p9keyr2.secrets[2], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p10keyr2.secrets[2], p10derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p6keyr2.secrets[3], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p7keyr2.secrets[3], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p8keyr2.secrets[3], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p9keyr2.secrets[3], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p10keyr2.secrets[3], p10derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p6keyr2.secrets[4], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p7keyr2.secrets[4], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p8keyr2.secrets[4], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p9keyr2.secrets[4], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p10keyr2.secrets[4], p10derivcommit, thresh-1)

		// participant6 checks the sending secret value.
		secretcheck(curve.Scalar.New(6), p1keyr2.secrets[5], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p2keyr2.secrets[5], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p3keyr2.secrets[5], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p4keyr2.secrets[5], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p5keyr2.secrets[5], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p6keyr2.secrets[5], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p7keyr2.secrets[5], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p8keyr2.secrets[5], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p9keyr2.secrets[5], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p10keyr2.secrets[5], p10derivcommit, thresh-1)

		// participant7 checks the sending secret value.
		secretcheck(curve.Scalar.New(7), p1keyr2.secrets[6], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p2keyr2.secrets[6], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p3keyr2.secrets[6], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p4keyr2.secrets[6], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p5keyr2.secrets[6], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p6keyr2.secrets[6], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p7keyr2.secrets[6], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p8keyr2.secrets[6], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p9keyr2.secrets[6], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p10keyr2.secrets[6], p10derivcommit, thresh-1)

		// participant8 checks the sending secret value.
		secretcheck(curve.Scalar.New(8), p1keyr2.secrets[7], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p2keyr2.secrets[7], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p3keyr2.secrets[7], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p4keyr2.secrets[7], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p5keyr2.secrets[7], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p6keyr2.secrets[7], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p7keyr2.secrets[7], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p8keyr2.secrets[7], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p9keyr2.secrets[7], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p10keyr2.secrets[7], p10derivcommit, thresh-1)

		// participant9 checks the sending secret value.
		secretcheck(curve.Scalar.New(9), p1keyr2.secrets[8], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p2keyr2.secrets[8], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p3keyr2.secrets[8], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p4keyr2.secrets[8], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p5keyr2.secrets[8], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p6keyr2.secrets[8], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p7keyr2.secrets[8], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p8keyr2.secrets[8], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p9keyr2.secrets[8], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p10keyr2.secrets[8], p10derivcommit, thresh-1)

		// participant10 checks the sending secret value.
		secretcheck(curve.Scalar.New(10), p1keyr2.secrets[9], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p2keyr2.secrets[9], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p3keyr2.secrets[9], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p4keyr2.secrets[9], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p5keyr2.secrets[9], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p6keyr2.secrets[9], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p7keyr2.secrets[9], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p8keyr2.secrets[9], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p9keyr2.secrets[9], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p10keyr2.secrets[9], p10derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0]).Add(p8keyr2.secrets[0]).Add(p9keyr2.secrets[0]).Add(p10keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1]).Add(p8keyr2.secrets[1]).Add(p9keyr2.secrets[1]).Add(p10keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2]).Add(p8keyr2.secrets[2]).Add(p9keyr2.secrets[2]).Add(p10keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3]).Add(p8keyr2.secrets[3]).Add(p9keyr2.secrets[3]).Add(p10keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4]).Add(p8keyr2.secrets[4]).Add(p9keyr2.secrets[4]).Add(p10keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5]).Add(p8keyr2.secrets[5]).Add(p9keyr2.secrets[5]).Add(p10keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6]).Add(p8keyr2.secrets[6]).Add(p9keyr2.secrets[6]).Add(p10keyr2.secrets[6])
		p8secret := p1keyr2.secrets[7].Add(p2keyr2.secrets[7]).Add(p3keyr2.secrets[7]).Add(p4keyr2.secrets[7]).Add(p5keyr2.secrets[7]).Add(p6keyr2.secrets[7]).Add(p7keyr2.secrets[7]).Add(p8keyr2.secrets[7]).Add(p9keyr2.secrets[7]).Add(p10keyr2.secrets[7])
		p9secret := p1keyr2.secrets[8].Add(p2keyr2.secrets[8]).Add(p3keyr2.secrets[8]).Add(p4keyr2.secrets[8]).Add(p5keyr2.secrets[8]).Add(p6keyr2.secrets[8]).Add(p7keyr2.secrets[8]).Add(p8keyr2.secrets[8]).Add(p9keyr2.secrets[8]).Add(p10keyr2.secrets[8])
		p10secret := p1keyr2.secrets[9].Add(p2keyr2.secrets[9]).Add(p3keyr2.secrets[9]).Add(p4keyr2.secrets[9]).Add(p5keyr2.secrets[9]).Add(p6keyr2.secrets[9]).Add(p7keyr2.secrets[9]).Add(p8keyr2.secrets[9]).Add(p9keyr2.secrets[9]).Add(p10keyr2.secrets[9])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)
		p8pub := curve.Point.Generator().Mul(p8secret)
		p9pub := curve.Point.Generator().Mul(p9secret)
		p10pub := curve.Point.Generator().Mul(p10secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub
		pubs[5] = p6pub
		pubs[6] = p7pub
		pubs[7] = p8pub
		pubs[8] = p9pub
		pubs[9] = p10pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0]).Add(p8keyr1.commit[0]).Add(p9keyr1.commit[0]).Add(p10keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		p8pre := new(preprocess).Init(curvetype)
		p9pre := new(preprocess).Init(curvetype)
		p10pre := new(preprocess).Init(curvetype)

		_ = p5pre
		_ = p6pre
		_ = p7pre
		_ = p8pre
		_ = p9pre
		_ = p10pre

		//Frost Sign (participant1, participant2 and participant3 and participant4 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Tassa 25519", duration/1000)
}

func TestPlainFROSTt4m10(t *testing.T) {
	// Plain FROST t=4 m=10
	start := time.Now()

	//KeyGen Round1
	thresh := 4
	number := 10
	curvetype := "25519"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)
		p8keyr1 := new(keygenr1).Init(thresh, curvetype)
		p9keyr1 := new(keygenr1).Init(thresh, curvetype)
		p10keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
			p8keyr1.sch.Verify(curvetype)
			p9keyr1.sch.Verify(curvetype)
			p10keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).Init(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).Init(number, p7keyr1, curvetype)
		p8keyr2 := new(keygenr2).Init(number, p8keyr1, curvetype)
		p9keyr2 := new(keygenr2).Init(number, p9keyr1, curvetype)
		p10keyr2 := new(keygenr2).Init(number, p10keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p6keyr2.secrets[i], p6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p7keyr2.secrets[i], p7keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p8keyr2.secrets[i], p8keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p9keyr2.secrets[i], p9keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p10keyr2.secrets[i], p10keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0]).Add(p8keyr2.secrets[0]).Add(p9keyr2.secrets[0]).Add(p10keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1]).Add(p8keyr2.secrets[1]).Add(p9keyr2.secrets[1]).Add(p10keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2]).Add(p8keyr2.secrets[2]).Add(p9keyr2.secrets[2]).Add(p10keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3]).Add(p8keyr2.secrets[3]).Add(p9keyr2.secrets[3]).Add(p10keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4]).Add(p8keyr2.secrets[4]).Add(p9keyr2.secrets[4]).Add(p10keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5]).Add(p8keyr2.secrets[5]).Add(p9keyr2.secrets[5]).Add(p10keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6]).Add(p8keyr2.secrets[6]).Add(p9keyr2.secrets[6]).Add(p10keyr2.secrets[6])
		p8secret := p1keyr2.secrets[7].Add(p2keyr2.secrets[7]).Add(p3keyr2.secrets[7]).Add(p4keyr2.secrets[7]).Add(p5keyr2.secrets[7]).Add(p6keyr2.secrets[7]).Add(p7keyr2.secrets[7]).Add(p8keyr2.secrets[7]).Add(p9keyr2.secrets[7]).Add(p10keyr2.secrets[7])
		p9secret := p1keyr2.secrets[8].Add(p2keyr2.secrets[8]).Add(p3keyr2.secrets[8]).Add(p4keyr2.secrets[8]).Add(p5keyr2.secrets[8]).Add(p6keyr2.secrets[8]).Add(p7keyr2.secrets[8]).Add(p8keyr2.secrets[8]).Add(p9keyr2.secrets[8]).Add(p10keyr2.secrets[8])
		p10secret := p1keyr2.secrets[9].Add(p2keyr2.secrets[9]).Add(p3keyr2.secrets[9]).Add(p4keyr2.secrets[9]).Add(p5keyr2.secrets[9]).Add(p6keyr2.secrets[9]).Add(p7keyr2.secrets[9]).Add(p8keyr2.secrets[9]).Add(p9keyr2.secrets[9]).Add(p10keyr2.secrets[9])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)
		p8pub := curve.Point.Generator().Mul(p8secret)
		p9pub := curve.Point.Generator().Mul(p9secret)
		p10pub := curve.Point.Generator().Mul(p10secret)

		_ = p5pub
		_ = p6pub
		_ = p7pub
		_ = p8pub
		_ = p9pub
		_ = p10pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0]).Add(p8keyr1.commit[0]).Add(p9keyr1.commit[0]).Add(p10keyr1.commit[0])
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		p8pre := new(preprocess).Init(curvetype)
		p9pre := new(preprocess).Init(curvetype)
		p10pre := new(preprocess).Init(curvetype)
		_ = p5pre
		_ = p6pre
		_ = p7pre
		_ = p8pre
		_ = p9pre
		_ = p10pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Plain 25519", duration/1000)

}

func TestOurSchemeFROSTt4m10(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "25519"
	curve := getCurve(curvetype)
	thresh := 3
	number := 10

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n5keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n6keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n7keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n8keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n9keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)
			l2n5keyr1.sch.Verify(curvetype)
			l2n6keyr1.sch.Verify(curvetype)
			l2n7keyr1.sch.Verify(curvetype)
			l2n8keyr1.sch.Verify(curvetype)
			l2n9keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		l2n5keyr2 := new(keygenr2).Init(number, l2n5keyr1, curvetype)
		l2n6keyr2 := new(keygenr2).Init(number, l2n6keyr1, curvetype)
		l2n7keyr2 := new(keygenr2).Init(number, l2n7keyr1, curvetype)
		l2n8keyr2 := new(keygenr2).Init(number, l2n8keyr1, curvetype)
		l2n9keyr2 := new(keygenr2).Init(number, l2n9keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n5keyr2.secrets[i], l2n5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n6keyr2.secrets[i], l2n6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n7keyr2.secrets[i], l2n7keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n8keyr2.secrets[i], l2n8keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n9keyr2.secrets[i], l2n9keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0]).Add(l2n5keyr2.secrets[0]).Add(l2n6keyr2.secrets[0]).Add(l2n7keyr2.secrets[0]).Add(l2n8keyr2.secrets[0]).Add(l2n9keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1]).Add(l2n5keyr2.secrets[1]).Add(l2n6keyr2.secrets[1]).Add(l2n7keyr2.secrets[1]).Add(l2n8keyr2.secrets[1]).Add(l2n9keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2]).Add(l2n5keyr2.secrets[2]).Add(l2n6keyr2.secrets[2]).Add(l2n7keyr2.secrets[2]).Add(l2n8keyr2.secrets[2]).Add(l2n9keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3]).Add(l2n5keyr2.secrets[3]).Add(l2n6keyr2.secrets[3]).Add(l2n7keyr2.secrets[3]).Add(l2n8keyr2.secrets[3]).Add(l2n9keyr2.secrets[3])
		l2n5secret := l2n1keyr2.secrets[4].Add(l2n2keyr2.secrets[4]).Add(l2n3keyr2.secrets[4]).Add(l2n4keyr2.secrets[4]).Add(l2n5keyr2.secrets[4]).Add(l2n6keyr2.secrets[4]).Add(l2n7keyr2.secrets[4]).Add(l2n8keyr2.secrets[4]).Add(l2n9keyr2.secrets[4])
		l2n6secret := l2n1keyr2.secrets[5].Add(l2n2keyr2.secrets[5]).Add(l2n3keyr2.secrets[5]).Add(l2n4keyr2.secrets[5]).Add(l2n5keyr2.secrets[5]).Add(l2n6keyr2.secrets[5]).Add(l2n7keyr2.secrets[5]).Add(l2n8keyr2.secrets[5]).Add(l2n9keyr2.secrets[5])
		l2n7secret := l2n1keyr2.secrets[6].Add(l2n2keyr2.secrets[6]).Add(l2n3keyr2.secrets[6]).Add(l2n4keyr2.secrets[6]).Add(l2n5keyr2.secrets[6]).Add(l2n6keyr2.secrets[6]).Add(l2n7keyr2.secrets[6]).Add(l2n8keyr2.secrets[6]).Add(l2n9keyr2.secrets[6])
		l2n8secret := l2n1keyr2.secrets[7].Add(l2n2keyr2.secrets[7]).Add(l2n3keyr2.secrets[7]).Add(l2n4keyr2.secrets[7]).Add(l2n5keyr2.secrets[7]).Add(l2n6keyr2.secrets[7]).Add(l2n7keyr2.secrets[7]).Add(l2n8keyr2.secrets[7]).Add(l2n9keyr2.secrets[7])
		l2n9secret := l2n1keyr2.secrets[8].Add(l2n2keyr2.secrets[8]).Add(l2n3keyr2.secrets[8]).Add(l2n4keyr2.secrets[8]).Add(l2n5keyr2.secrets[8]).Add(l2n6keyr2.secrets[8]).Add(l2n7keyr2.secrets[8]).Add(l2n8keyr2.secrets[8]).Add(l2n9keyr2.secrets[8])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)
		l2n5pub := curve.Point.Generator().Mul(l2n5secret)
		l2n6pub := curve.Point.Generator().Mul(l2n6secret)
		l2n7pub := curve.Point.Generator().Mul(l2n7secret)
		l2n8pub := curve.Point.Generator().Mul(l2n8secret)
		l2n9pub := curve.Point.Generator().Mul(l2n9secret)

		_ = l2n4pub
		_ = l2n5pub
		_ = l2n6pub
		_ = l2n7pub
		_ = l2n8pub
		_ = l2n9pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0]).Add(l2n5keyr1.commit[0]).Add(l2n6keyr1.commit[0]).Add(l2n7keyr1.commit[0]).Add(l2n8keyr1.commit[0]).Add(l2n9keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		l2n5pre := new(preprocess).Init(curvetype)
		l2n6pre := new(preprocess).Init(curvetype)
		l2n7pre := new(preprocess).Init(curvetype)
		l2n8pre := new(preprocess).Init(curvetype)
		l2n9pre := new(preprocess).Init(curvetype)

		_ = l2n4pre
		_ = l2n5pre
		_ = l2n6pre
		_ = l2n7pre
		_ = l2n8pre
		_ = l2n9pre
		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Our 25519", duration/1000)

}

//////////////////////////////

func TestP256TassaFROSTt3m4(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()

	//KeyGen Round1
	thresh := 3
	number := 4
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {

		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)

		pubs := make([]curves.Point, 4)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0])

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
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))

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
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Tassa p256", duration/1000)

}
func TestP256PlainFROSTt3m4(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 3
	number := 4
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
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
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub)

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
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Plain p256", duration/1000)

}

func TestP256OurSchemeFROSTt3m4(t *testing.T) {
	// Hierarc. FROST (1,1) (2,3)
	start := time.Now()
	// Level1 Keygen

	curvetype := "p256"
	curve := getCurve(curvetype)
	thresh := 2
	number := 3

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

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

		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
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

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t3 m4 Our p256", duration/1000)

}

func TestP256TassaFROSTt4m5(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 5
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		_ = p5pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m5 Tassa p256", duration/1000)
}

func TestP256PlainFROSTt4m5(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 5
	curvetype := "p256"
	curve := getCurve(curvetype)
	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)

		_ = p5pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0])

		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		_ = p5pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}

	duration := time.Since(start)
	fmt.Println("t4 m5 Plain p256", duration/1000)
}

func TestP256OurSchemeFROSTt4m5(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "p256"
	curve := getCurve(curvetype)
	thresh := 3
	number := 4

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)

		_ = l2n4pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		_ = l2n4pre

		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}

	duration := time.Since(start)
	fmt.Println("t4 m5 Our p256", duration/1000)
}

func TestP256TassaFROSTt4m7(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 7
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).TassaInit(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).TassaInit(number, p7keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)
		p6derivcommit := derivcommit(p6keyr1.commit, curvetype)
		p7derivcommit := derivcommit(p7keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p6keyr2.secrets[0], p6keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p7keyr2.secrets[0], p7keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p6keyr2.secrets[1], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p7keyr2.secrets[1], p7derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p6keyr2.secrets[2], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p7keyr2.secrets[2], p7derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p6keyr2.secrets[3], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p7keyr2.secrets[3], p7derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p6keyr2.secrets[4], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p7keyr2.secrets[4], p7derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(6), p1keyr2.secrets[5], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p2keyr2.secrets[5], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p3keyr2.secrets[5], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p4keyr2.secrets[5], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p5keyr2.secrets[5], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p6keyr2.secrets[5], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p7keyr2.secrets[5], p7derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(7), p1keyr2.secrets[6], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p2keyr2.secrets[6], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p3keyr2.secrets[6], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p4keyr2.secrets[6], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p5keyr2.secrets[6], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p6keyr2.secrets[6], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p7keyr2.secrets[6], p7derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub
		pubs[5] = p6pub
		pubs[6] = p7pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)

		_ = p5pre
		_ = p6pre
		_ = p7pre

		//Frost Sign (participant1, participant2 and participant3 and participant4 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Tassa p256", duration/1000)
}

func TestP256PlainFROSTt4m7(t *testing.T) {
	// Plain FROST t=3 m=4
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 7
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).Init(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).Init(number, p7keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p6keyr2.secrets[i], p6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p7keyr2.secrets[i], p7keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)

		_ = p5pub
		_ = p6pub
		_ = p7pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0])

		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		_ = p5pre
		_ = p6pre
		_ = p7pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Plain p256", duration/1000)
}

func TestP256OurSchemeFROSTt4m7(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "p256"
	curve := getCurve(curvetype)
	thresh := 3
	number := 7
	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n5keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n6keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)
			l2n5keyr1.sch.Verify(curvetype)
			l2n6keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		l2n5keyr2 := new(keygenr2).Init(number, l2n5keyr1, curvetype)
		l2n6keyr2 := new(keygenr2).Init(number, l2n6keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n5keyr2.secrets[i], l2n5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n6keyr2.secrets[i], l2n6keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0]).Add(l2n5keyr2.secrets[0]).Add(l2n6keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1]).Add(l2n5keyr2.secrets[1]).Add(l2n6keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2]).Add(l2n5keyr2.secrets[2]).Add(l2n6keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3]).Add(l2n5keyr2.secrets[3]).Add(l2n6keyr2.secrets[3])
		l2n5secret := l2n1keyr2.secrets[4].Add(l2n2keyr2.secrets[4]).Add(l2n3keyr2.secrets[4]).Add(l2n4keyr2.secrets[4]).Add(l2n5keyr2.secrets[4]).Add(l2n6keyr2.secrets[4])
		l2n6secret := l2n1keyr2.secrets[5].Add(l2n2keyr2.secrets[5]).Add(l2n3keyr2.secrets[5]).Add(l2n4keyr2.secrets[5]).Add(l2n5keyr2.secrets[5]).Add(l2n6keyr2.secrets[5])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)
		l2n5pub := curve.Point.Generator().Mul(l2n5secret)
		l2n6pub := curve.Point.Generator().Mul(l2n6secret)

		_ = l2n4pub
		_ = l2n5pub
		_ = l2n6pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0]).Add(l2n5keyr1.commit[0]).Add(l2n6keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		l2n5pre := new(preprocess).Init(curvetype)
		l2n6pre := new(preprocess).Init(curvetype)

		_ = l2n4pre
		_ = l2n5pre
		_ = l2n6pre
		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m7 Our p256", duration/1000)

}

func TestP256TassaFROSTt4m10(t *testing.T) {
	// Tassa FROST 1 boss
	start := time.Now()
	//KeyGen Round1
	thresh := 4
	number := 10
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)
		p8keyr1 := new(keygenr1).Init(thresh, curvetype)
		p9keyr1 := new(keygenr1).Init(thresh, curvetype)
		p10keyr1 := new(keygenr1).Init(thresh, curvetype)

		//
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
			p8keyr1.sch.Verify(curvetype)
			p9keyr1.sch.Verify(curvetype)
			p10keyr1.sch.Verify(curvetype)
		}

		p1keyr2 := new(keygenr2).TassaInit(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).TassaInit(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).TassaInit(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).TassaInit(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).TassaInit(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).TassaInit(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).TassaInit(number, p7keyr1, curvetype)
		p8keyr2 := new(keygenr2).TassaInit(number, p8keyr1, curvetype)
		p9keyr2 := new(keygenr2).TassaInit(number, p9keyr1, curvetype)
		p10keyr2 := new(keygenr2).TassaInit(number, p10keyr1, curvetype)

		p1derivcommit := derivcommit(p1keyr1.commit, curvetype)
		p2derivcommit := derivcommit(p2keyr1.commit, curvetype)
		p3derivcommit := derivcommit(p3keyr1.commit, curvetype)
		p4derivcommit := derivcommit(p4keyr1.commit, curvetype)
		p5derivcommit := derivcommit(p5keyr1.commit, curvetype)
		p6derivcommit := derivcommit(p6keyr1.commit, curvetype)
		p7derivcommit := derivcommit(p7keyr1.commit, curvetype)
		p8derivcommit := derivcommit(p8keyr1.commit, curvetype)
		p9derivcommit := derivcommit(p9keyr1.commit, curvetype)
		p10derivcommit := derivcommit(p10keyr1.commit, curvetype)

		//to illustrate
		/*
			for i := 0; i < 2; i++ {
				p1derivcommit = derivcommit(p1keyr1.commit, curvetype)
				p2derivcommit = derivcommit(p2keyr1.commit, curvetype)
				p3derivcommit = derivcommit(p3keyr1.commit, curvetype)
				p4derivcommit = derivcommit(p4keyr1.commit, curvetype)

			}
		*/

		//calculate commit derivative ...
		// participant1 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh))
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh))
		secretcheck(curve.Scalar.New(1), p1keyr2.secrets[0], p1keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p2keyr2.secrets[0], p2keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p3keyr2.secrets[0], p3keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p4keyr2.secrets[0], p4keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p5keyr2.secrets[0], p5keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p6keyr2.secrets[0], p6keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p7keyr2.secrets[0], p7keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p8keyr2.secrets[0], p8keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p9keyr2.secrets[0], p9keyr1.commit, thresh)
		secretcheck(curve.Scalar.New(1), p10keyr2.secrets[0], p10keyr1.commit, thresh)

		// participant2 checks the sending secret value.
		//fmt.Printf("%t", secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(2), p1keyr2.secrets[1], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p2keyr2.secrets[1], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p3keyr2.secrets[1], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p4keyr2.secrets[1], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p5keyr2.secrets[1], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p6keyr2.secrets[1], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p7keyr2.secrets[1], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p8keyr2.secrets[1], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p9keyr2.secrets[1], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(2), p10keyr2.secrets[1], p10derivcommit, thresh-1)

		// participant3 checks the sending secret value.
		// fmt.Printf("%t", secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1))
		secretcheck(curve.Scalar.New(3), p1keyr2.secrets[2], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p2keyr2.secrets[2], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p3keyr2.secrets[2], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p4keyr2.secrets[2], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p5keyr2.secrets[2], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p6keyr2.secrets[2], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p7keyr2.secrets[2], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p8keyr2.secrets[2], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p9keyr2.secrets[2], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(3), p10keyr2.secrets[2], p10derivcommit, thresh-1)

		// participant4 checks the sending secret value.
		secretcheck(curve.Scalar.New(4), p1keyr2.secrets[3], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p2keyr2.secrets[3], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p3keyr2.secrets[3], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p4keyr2.secrets[3], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p5keyr2.secrets[3], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p6keyr2.secrets[3], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p7keyr2.secrets[3], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p8keyr2.secrets[3], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p9keyr2.secrets[3], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(4), p10keyr2.secrets[3], p10derivcommit, thresh-1)

		// participant5 checks the sending secret value.
		secretcheck(curve.Scalar.New(5), p1keyr2.secrets[4], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p2keyr2.secrets[4], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p3keyr2.secrets[4], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p4keyr2.secrets[4], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p5keyr2.secrets[4], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p6keyr2.secrets[4], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p7keyr2.secrets[4], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p8keyr2.secrets[4], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p9keyr2.secrets[4], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(5), p10keyr2.secrets[4], p10derivcommit, thresh-1)

		// participant6 checks the sending secret value.
		secretcheck(curve.Scalar.New(6), p1keyr2.secrets[5], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p2keyr2.secrets[5], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p3keyr2.secrets[5], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p4keyr2.secrets[5], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p5keyr2.secrets[5], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p6keyr2.secrets[5], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p7keyr2.secrets[5], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p8keyr2.secrets[5], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p9keyr2.secrets[5], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(6), p10keyr2.secrets[5], p10derivcommit, thresh-1)

		// participant7 checks the sending secret value.
		secretcheck(curve.Scalar.New(7), p1keyr2.secrets[6], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p2keyr2.secrets[6], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p3keyr2.secrets[6], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p4keyr2.secrets[6], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p5keyr2.secrets[6], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p6keyr2.secrets[6], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p7keyr2.secrets[6], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p8keyr2.secrets[6], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p9keyr2.secrets[6], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(7), p10keyr2.secrets[6], p10derivcommit, thresh-1)

		// participant8 checks the sending secret value.
		secretcheck(curve.Scalar.New(8), p1keyr2.secrets[7], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p2keyr2.secrets[7], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p3keyr2.secrets[7], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p4keyr2.secrets[7], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p5keyr2.secrets[7], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p6keyr2.secrets[7], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p7keyr2.secrets[7], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p8keyr2.secrets[7], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p9keyr2.secrets[7], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(8), p10keyr2.secrets[7], p10derivcommit, thresh-1)

		// participant9 checks the sending secret value.
		secretcheck(curve.Scalar.New(9), p1keyr2.secrets[8], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p2keyr2.secrets[8], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p3keyr2.secrets[8], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p4keyr2.secrets[8], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p5keyr2.secrets[8], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p6keyr2.secrets[8], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p7keyr2.secrets[8], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p8keyr2.secrets[8], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p9keyr2.secrets[8], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(9), p10keyr2.secrets[8], p10derivcommit, thresh-1)

		// participant10 checks the sending secret value.
		secretcheck(curve.Scalar.New(10), p1keyr2.secrets[9], p1derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p2keyr2.secrets[9], p2derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p3keyr2.secrets[9], p3derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p4keyr2.secrets[9], p4derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p5keyr2.secrets[9], p5derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p6keyr2.secrets[9], p6derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p7keyr2.secrets[9], p7derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p8keyr2.secrets[9], p8derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p9keyr2.secrets[9], p9derivcommit, thresh-1)
		secretcheck(curve.Scalar.New(10), p10keyr2.secrets[9], p10derivcommit, thresh-1)

		// add secrets and calculate sharing keys
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0]).Add(p8keyr2.secrets[0]).Add(p9keyr2.secrets[0]).Add(p10keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1]).Add(p8keyr2.secrets[1]).Add(p9keyr2.secrets[1]).Add(p10keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2]).Add(p8keyr2.secrets[2]).Add(p9keyr2.secrets[2]).Add(p10keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3]).Add(p8keyr2.secrets[3]).Add(p9keyr2.secrets[3]).Add(p10keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4]).Add(p8keyr2.secrets[4]).Add(p9keyr2.secrets[4]).Add(p10keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5]).Add(p8keyr2.secrets[5]).Add(p9keyr2.secrets[5]).Add(p10keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6]).Add(p8keyr2.secrets[6]).Add(p9keyr2.secrets[6]).Add(p10keyr2.secrets[6])
		p8secret := p1keyr2.secrets[7].Add(p2keyr2.secrets[7]).Add(p3keyr2.secrets[7]).Add(p4keyr2.secrets[7]).Add(p5keyr2.secrets[7]).Add(p6keyr2.secrets[7]).Add(p7keyr2.secrets[7]).Add(p8keyr2.secrets[7]).Add(p9keyr2.secrets[7]).Add(p10keyr2.secrets[7])
		p9secret := p1keyr2.secrets[8].Add(p2keyr2.secrets[8]).Add(p3keyr2.secrets[8]).Add(p4keyr2.secrets[8]).Add(p5keyr2.secrets[8]).Add(p6keyr2.secrets[8]).Add(p7keyr2.secrets[8]).Add(p8keyr2.secrets[8]).Add(p9keyr2.secrets[8]).Add(p10keyr2.secrets[8])
		p10secret := p1keyr2.secrets[9].Add(p2keyr2.secrets[9]).Add(p3keyr2.secrets[9]).Add(p4keyr2.secrets[9]).Add(p5keyr2.secrets[9]).Add(p6keyr2.secrets[9]).Add(p7keyr2.secrets[9]).Add(p8keyr2.secrets[9]).Add(p9keyr2.secrets[9]).Add(p10keyr2.secrets[9])

		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)
		p8pub := curve.Point.Generator().Mul(p8secret)
		p9pub := curve.Point.Generator().Mul(p9secret)
		p10pub := curve.Point.Generator().Mul(p10secret)

		pubs := make([]curves.Point, number)
		pubs[0] = p1pub
		pubs[1] = p2pub
		pubs[2] = p3pub
		pubs[3] = p4pub
		pubs[4] = p5pub
		pubs[5] = p6pub
		pubs[6] = p7pub
		pubs[7] = p8pub
		pubs[8] = p9pub
		pubs[9] = p10pub

		//check simdilik coef yok, varmış gibi yapıyorum.
		//mış gibi
		coef := make([]curves.Scalar, number)
		for i := 0; i < number; i++ {
			coef[i] = curve.Scalar.Random(rand.Reader)
		}

		/*
			lhs := curve.Point.Identity()
			rhs := curve.Point.Identity()
			for i := 0; i < thresh; i++ {
				lhs = lhs.Add(pubs[i].Mul(coef[i]))
				rhs = rhs.Add(p1keyr1.commit[i])
			}
		*/

		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0]).Add(p8keyr1.commit[0]).Add(p9keyr1.commit[0]).Add(p10keyr1.commit[0])

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		p8pre := new(preprocess).Init(curvetype)
		p9pre := new(preprocess).Init(curvetype)
		p10pre := new(preprocess).Init(curvetype)

		_ = p5pre
		_ = p6pre
		_ = p7pre
		_ = p8pre
		_ = p9pre
		_ = p10pre

		//Frost Sign (participant1, participant2 and participant3 and participant4 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(coef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(coef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(coef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(coef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(coef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(coef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(coef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(coef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Tassa p256", duration/1000)
}

func TestP256PlainFROSTt4m10(t *testing.T) {
	// Plain FROST t=4 m=10
	start := time.Now()

	//KeyGen Round1
	thresh := 4
	number := 10
	curvetype := "p256"
	curve := getCurve(curvetype)

	for i := 0; i < 1000; i++ {
		//FROST Keygen Round1.1-2-3
		p1keyr1 := new(keygenr1).Init(thresh, curvetype)
		p2keyr1 := new(keygenr1).Init(thresh, curvetype)
		p3keyr1 := new(keygenr1).Init(thresh, curvetype)
		p4keyr1 := new(keygenr1).Init(thresh, curvetype)
		p5keyr1 := new(keygenr1).Init(thresh, curvetype)
		p6keyr1 := new(keygenr1).Init(thresh, curvetype)
		p7keyr1 := new(keygenr1).Init(thresh, curvetype)
		p8keyr1 := new(keygenr1).Init(thresh, curvetype)
		p9keyr1 := new(keygenr1).Init(thresh, curvetype)
		p10keyr1 := new(keygenr1).Init(thresh, curvetype)

		//FROST Keygen Round1.5
		for i := 0; i < (number - 1); i++ {
			p1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			p2keyr1.sch.Verify(curvetype)
			p3keyr1.sch.Verify(curvetype)
			p4keyr1.sch.Verify(curvetype)
			p5keyr1.sch.Verify(curvetype)
			p6keyr1.sch.Verify(curvetype)
			p7keyr1.sch.Verify(curvetype)
			p8keyr1.sch.Verify(curvetype)
			p9keyr1.sch.Verify(curvetype)
			p10keyr1.sch.Verify(curvetype)
		}

		//KeyGen Round2
		p1keyr2 := new(keygenr2).Init(number, p1keyr1, curvetype)
		p2keyr2 := new(keygenr2).Init(number, p2keyr1, curvetype)
		p3keyr2 := new(keygenr2).Init(number, p3keyr1, curvetype)
		p4keyr2 := new(keygenr2).Init(number, p4keyr1, curvetype)
		p5keyr2 := new(keygenr2).Init(number, p5keyr1, curvetype)
		p6keyr2 := new(keygenr2).Init(number, p6keyr1, curvetype)
		p7keyr2 := new(keygenr2).Init(number, p7keyr1, curvetype)
		p8keyr2 := new(keygenr2).Init(number, p8keyr1, curvetype)
		p9keyr2 := new(keygenr2).Init(number, p9keyr1, curvetype)
		p10keyr2 := new(keygenr2).Init(number, p10keyr1, curvetype)
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
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh))
			}
		*/

		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), p1keyr2.secrets[i], p1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p2keyr2.secrets[i], p2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p3keyr2.secrets[i], p3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p4keyr2.secrets[i], p4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p5keyr2.secrets[i], p5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p6keyr2.secrets[i], p6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p7keyr2.secrets[i], p7keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p8keyr2.secrets[i], p8keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p9keyr2.secrets[i], p9keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), p10keyr2.secrets[i], p10keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys FROST Keygen Round2.3
		p1secret := p1keyr2.secrets[0].Add(p2keyr2.secrets[0]).Add(p3keyr2.secrets[0]).Add(p4keyr2.secrets[0]).Add(p5keyr2.secrets[0]).Add(p6keyr2.secrets[0]).Add(p7keyr2.secrets[0]).Add(p8keyr2.secrets[0]).Add(p9keyr2.secrets[0]).Add(p10keyr2.secrets[0])
		p2secret := p1keyr2.secrets[1].Add(p2keyr2.secrets[1]).Add(p3keyr2.secrets[1]).Add(p4keyr2.secrets[1]).Add(p5keyr2.secrets[1]).Add(p6keyr2.secrets[1]).Add(p7keyr2.secrets[1]).Add(p8keyr2.secrets[1]).Add(p9keyr2.secrets[1]).Add(p10keyr2.secrets[1])
		p3secret := p1keyr2.secrets[2].Add(p2keyr2.secrets[2]).Add(p3keyr2.secrets[2]).Add(p4keyr2.secrets[2]).Add(p5keyr2.secrets[2]).Add(p6keyr2.secrets[2]).Add(p7keyr2.secrets[2]).Add(p8keyr2.secrets[2]).Add(p9keyr2.secrets[2]).Add(p10keyr2.secrets[2])
		p4secret := p1keyr2.secrets[3].Add(p2keyr2.secrets[3]).Add(p3keyr2.secrets[3]).Add(p4keyr2.secrets[3]).Add(p5keyr2.secrets[3]).Add(p6keyr2.secrets[3]).Add(p7keyr2.secrets[3]).Add(p8keyr2.secrets[3]).Add(p9keyr2.secrets[3]).Add(p10keyr2.secrets[3])
		p5secret := p1keyr2.secrets[4].Add(p2keyr2.secrets[4]).Add(p3keyr2.secrets[4]).Add(p4keyr2.secrets[4]).Add(p5keyr2.secrets[4]).Add(p6keyr2.secrets[4]).Add(p7keyr2.secrets[4]).Add(p8keyr2.secrets[4]).Add(p9keyr2.secrets[4]).Add(p10keyr2.secrets[4])
		p6secret := p1keyr2.secrets[5].Add(p2keyr2.secrets[5]).Add(p3keyr2.secrets[5]).Add(p4keyr2.secrets[5]).Add(p5keyr2.secrets[5]).Add(p6keyr2.secrets[5]).Add(p7keyr2.secrets[5]).Add(p8keyr2.secrets[5]).Add(p9keyr2.secrets[5]).Add(p10keyr2.secrets[5])
		p7secret := p1keyr2.secrets[6].Add(p2keyr2.secrets[6]).Add(p3keyr2.secrets[6]).Add(p4keyr2.secrets[6]).Add(p5keyr2.secrets[6]).Add(p6keyr2.secrets[6]).Add(p7keyr2.secrets[6]).Add(p8keyr2.secrets[6]).Add(p9keyr2.secrets[6]).Add(p10keyr2.secrets[6])
		p8secret := p1keyr2.secrets[7].Add(p2keyr2.secrets[7]).Add(p3keyr2.secrets[7]).Add(p4keyr2.secrets[7]).Add(p5keyr2.secrets[7]).Add(p6keyr2.secrets[7]).Add(p7keyr2.secrets[7]).Add(p8keyr2.secrets[7]).Add(p9keyr2.secrets[7]).Add(p10keyr2.secrets[7])
		p9secret := p1keyr2.secrets[8].Add(p2keyr2.secrets[8]).Add(p3keyr2.secrets[8]).Add(p4keyr2.secrets[8]).Add(p5keyr2.secrets[8]).Add(p6keyr2.secrets[8]).Add(p7keyr2.secrets[8]).Add(p8keyr2.secrets[8]).Add(p9keyr2.secrets[8]).Add(p10keyr2.secrets[8])
		p10secret := p1keyr2.secrets[9].Add(p2keyr2.secrets[9]).Add(p3keyr2.secrets[9]).Add(p4keyr2.secrets[9]).Add(p5keyr2.secrets[9]).Add(p6keyr2.secrets[9]).Add(p7keyr2.secrets[9]).Add(p8keyr2.secrets[9]).Add(p9keyr2.secrets[9]).Add(p10keyr2.secrets[9])

		// calculates participants public key FROST Keygen Round2.4
		p1pub := curve.Point.Generator().Mul(p1secret)
		p2pub := curve.Point.Generator().Mul(p2secret)
		p3pub := curve.Point.Generator().Mul(p3secret)
		p4pub := curve.Point.Generator().Mul(p4secret)
		p5pub := curve.Point.Generator().Mul(p5secret)
		p6pub := curve.Point.Generator().Mul(p6secret)
		p7pub := curve.Point.Generator().Mul(p7secret)
		p8pub := curve.Point.Generator().Mul(p8secret)
		p9pub := curve.Point.Generator().Mul(p9secret)
		p10pub := curve.Point.Generator().Mul(p10secret)

		_ = p5pub
		_ = p6pub
		_ = p7pub
		_ = p8pub
		_ = p9pub
		_ = p10pub
		// calculates group's public key FROST Keygen Round2.4
		grouppub := p1keyr1.commit[0].Add(p2keyr1.commit[0]).Add(p3keyr1.commit[0]).Add(p4keyr1.commit[0]).Add(p5keyr1.commit[0]).Add(p6keyr1.commit[0]).Add(p7keyr1.commit[0]).Add(p8keyr1.commit[0]).Add(p9keyr1.commit[0]).Add(p10keyr1.commit[0])
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		list[3] = curve.Scalar.New(4)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		// check!
		// fmt.Printf("%t", p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Equal(grouppub))
		p1pub.Mul(lcoef[0]).Add(p2pub.Mul(lcoef[1])).Add(p3pub.Mul(lcoef[2])).Add(p4pub.Mul(lcoef[3])).Equal(grouppub)

		//FROST Preprocess. For simplicity, use 1 nonce
		p1pre := new(preprocess).Init(curvetype)
		p2pre := new(preprocess).Init(curvetype)
		p3pre := new(preprocess).Init(curvetype)
		p4pre := new(preprocess).Init(curvetype)
		p5pre := new(preprocess).Init(curvetype)
		p6pre := new(preprocess).Init(curvetype)
		p7pre := new(preprocess).Init(curvetype)
		p8pre := new(preprocess).Init(curvetype)
		p9pre := new(preprocess).Init(curvetype)
		p10pre := new(preprocess).Init(curvetype)
		_ = p5pre
		_ = p6pre
		_ = p7pre
		_ = p8pre
		_ = p9pre
		_ = p10pre

		//Frost Sign (participant1, participant2 and participant3 join the sign phase)

		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*thresh)
		nonces[0] = p1pre.noncecommit[0]
		nonces[1] = p1pre.noncecommit[1]
		nonces[2] = p2pre.noncecommit[0]
		nonces[3] = p2pre.noncecommit[1]
		nonces[4] = p3pre.noncecommit[0]
		nonces[5] = p3pre.noncecommit[1]
		nonces[6] = p4pre.noncecommit[0]
		nonces[7] = p4pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, thresh)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, grouppub, message, curvetype)

		// each Participant computes their sign
		p1sign := p1pre.nonce[0].Add(p1pre.nonce[1].Mul(ro1)).Add(lcoef[0].Mul(p1secret).Mul(c))
		p2sign := p2pre.nonce[0].Add(p2pre.nonce[1].Mul(ro2)).Add(lcoef[1].Mul(p2secret).Mul(c))
		p3sign := p3pre.nonce[0].Add(p3pre.nonce[1].Mul(ro3)).Add(lcoef[2].Mul(p3secret).Mul(c))
		p4sign := p4pre.nonce[0].Add(p4pre.nonce[1].Mul(ro4)).Add(lcoef[3].Mul(p4secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := p1pre.noncecommit[0].Add(p1pre.noncecommit[1].Mul(ro1))
		R2 := p2pre.noncecommit[0].Add(p2pre.noncecommit[1].Mul(ro2))
		R3 := p3pre.noncecommit[0].Add(p3pre.noncecommit[1].Mul(ro3))
		R4 := p4pre.noncecommit[0].Add(p4pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, grouppub, message, curvetype)
		// fmt.Printf("%t", R.Equal(saR))

		//check pisign.G =? R_i + (c*lagrangei)Y_i
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0])))))
		// fmt.Printf("%t ", curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1])))))
		//fmt.Printf("%t ", curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3])))))

		curve.Point.Generator().Mul(p1sign).Equal(R1.Add(p1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(p2sign).Equal(R2.Add(p2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(p3sign).Equal(R3.Add(p3pub.Mul(sac.Mul(lcoef[2]))))
		curve.Point.Generator().Mul(p4sign).Equal(R4.Add(p4pub.Mul(sac.Mul(lcoef[3]))))
		// compute sign

		sign := p1sign.Add(p2sign).Add(p3sign).Add(p4sign)

		_ = sign
	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Plain p256", duration/1000)

}

func TestP256OurSchemeFROSTt4m10(t *testing.T) {
	// Hierarc. FROST (1,1) (3,4)
	start := time.Now()
	// Level1 Keygen

	curvetype := "p256"
	curve := getCurve(curvetype)
	thresh := 3
	number := 10

	for i := 0; i < 1000; i++ {
		l1secret := curve.Scalar.Random(rand.Reader)
		l1pub := curve.Point.Generator().Mul(l1secret)

		// Level2 Keygen

		l2n1keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n2keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n3keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n4keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n5keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n6keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n7keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n8keyr1 := new(keygenr1).Init(thresh, curvetype)
		l2n9keyr1 := new(keygenr1).Init(thresh, curvetype)

		for i := 0; i < (number - 1); i++ {
			l2n1keyr1.sch.Verify(curvetype)
			//fmt.Printf("%e", p1keyr1.sch.Verify(curvetype))
			l2n2keyr1.sch.Verify(curvetype)
			l2n3keyr1.sch.Verify(curvetype)
			l2n4keyr1.sch.Verify(curvetype)
			l2n5keyr1.sch.Verify(curvetype)
			l2n6keyr1.sch.Verify(curvetype)
			l2n7keyr1.sch.Verify(curvetype)
			l2n8keyr1.sch.Verify(curvetype)
			l2n9keyr1.sch.Verify(curvetype)

		}

		//KeyGen Round2
		l2n1keyr2 := new(keygenr2).Init(number, l2n1keyr1, curvetype)
		l2n2keyr2 := new(keygenr2).Init(number, l2n2keyr1, curvetype)
		l2n3keyr2 := new(keygenr2).Init(number, l2n3keyr1, curvetype)
		l2n4keyr2 := new(keygenr2).Init(number, l2n4keyr1, curvetype)
		l2n5keyr2 := new(keygenr2).Init(number, l2n5keyr1, curvetype)
		l2n6keyr2 := new(keygenr2).Init(number, l2n6keyr1, curvetype)
		l2n7keyr2 := new(keygenr2).Init(number, l2n7keyr1, curvetype)
		l2n8keyr2 := new(keygenr2).Init(number, l2n8keyr1, curvetype)
		l2n9keyr2 := new(keygenr2).Init(number, l2n9keyr1, curvetype)
		/*
			for i := 0; i < number; i++ {
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh))
				fmt.Printf("%t", secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh))
			}
		*/
		for i := 0; i < number; i++ {
			secretcheck(curve.Scalar.New(i+1), l2n1keyr2.secrets[i], l2n1keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n2keyr2.secrets[i], l2n2keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n3keyr2.secrets[i], l2n3keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n4keyr2.secrets[i], l2n4keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n5keyr2.secrets[i], l2n5keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n6keyr2.secrets[i], l2n6keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n7keyr2.secrets[i], l2n7keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n8keyr2.secrets[i], l2n8keyr1.commit, thresh)
			secretcheck(curve.Scalar.New(i+1), l2n9keyr2.secrets[i], l2n9keyr1.commit, thresh)
		}

		// add secrets and calculate sharing keys
		l2n1secret := l2n1keyr2.secrets[0].Add(l2n2keyr2.secrets[0]).Add(l2n3keyr2.secrets[0]).Add(l2n4keyr2.secrets[0]).Add(l2n5keyr2.secrets[0]).Add(l2n6keyr2.secrets[0]).Add(l2n7keyr2.secrets[0]).Add(l2n8keyr2.secrets[0]).Add(l2n9keyr2.secrets[0])
		l2n2secret := l2n1keyr2.secrets[1].Add(l2n2keyr2.secrets[1]).Add(l2n3keyr2.secrets[1]).Add(l2n4keyr2.secrets[1]).Add(l2n5keyr2.secrets[1]).Add(l2n6keyr2.secrets[1]).Add(l2n7keyr2.secrets[1]).Add(l2n8keyr2.secrets[1]).Add(l2n9keyr2.secrets[1])
		l2n3secret := l2n1keyr2.secrets[2].Add(l2n2keyr2.secrets[2]).Add(l2n3keyr2.secrets[2]).Add(l2n4keyr2.secrets[2]).Add(l2n5keyr2.secrets[2]).Add(l2n6keyr2.secrets[2]).Add(l2n7keyr2.secrets[2]).Add(l2n8keyr2.secrets[2]).Add(l2n9keyr2.secrets[2])
		l2n4secret := l2n1keyr2.secrets[3].Add(l2n2keyr2.secrets[3]).Add(l2n3keyr2.secrets[3]).Add(l2n4keyr2.secrets[3]).Add(l2n5keyr2.secrets[3]).Add(l2n6keyr2.secrets[3]).Add(l2n7keyr2.secrets[3]).Add(l2n8keyr2.secrets[3]).Add(l2n9keyr2.secrets[3])
		l2n5secret := l2n1keyr2.secrets[4].Add(l2n2keyr2.secrets[4]).Add(l2n3keyr2.secrets[4]).Add(l2n4keyr2.secrets[4]).Add(l2n5keyr2.secrets[4]).Add(l2n6keyr2.secrets[4]).Add(l2n7keyr2.secrets[4]).Add(l2n8keyr2.secrets[4]).Add(l2n9keyr2.secrets[4])
		l2n6secret := l2n1keyr2.secrets[5].Add(l2n2keyr2.secrets[5]).Add(l2n3keyr2.secrets[5]).Add(l2n4keyr2.secrets[5]).Add(l2n5keyr2.secrets[5]).Add(l2n6keyr2.secrets[5]).Add(l2n7keyr2.secrets[5]).Add(l2n8keyr2.secrets[5]).Add(l2n9keyr2.secrets[5])
		l2n7secret := l2n1keyr2.secrets[6].Add(l2n2keyr2.secrets[6]).Add(l2n3keyr2.secrets[6]).Add(l2n4keyr2.secrets[6]).Add(l2n5keyr2.secrets[6]).Add(l2n6keyr2.secrets[6]).Add(l2n7keyr2.secrets[6]).Add(l2n8keyr2.secrets[6]).Add(l2n9keyr2.secrets[6])
		l2n8secret := l2n1keyr2.secrets[7].Add(l2n2keyr2.secrets[7]).Add(l2n3keyr2.secrets[7]).Add(l2n4keyr2.secrets[7]).Add(l2n5keyr2.secrets[7]).Add(l2n6keyr2.secrets[7]).Add(l2n7keyr2.secrets[7]).Add(l2n8keyr2.secrets[7]).Add(l2n9keyr2.secrets[7])
		l2n9secret := l2n1keyr2.secrets[8].Add(l2n2keyr2.secrets[8]).Add(l2n3keyr2.secrets[8]).Add(l2n4keyr2.secrets[8]).Add(l2n5keyr2.secrets[8]).Add(l2n6keyr2.secrets[8]).Add(l2n7keyr2.secrets[8]).Add(l2n8keyr2.secrets[8]).Add(l2n9keyr2.secrets[8])

		// calculates level2nodes public key
		l2n1pub := curve.Point.Generator().Mul(l2n1secret)
		l2n2pub := curve.Point.Generator().Mul(l2n2secret)
		l2n3pub := curve.Point.Generator().Mul(l2n3secret)
		l2n4pub := curve.Point.Generator().Mul(l2n4secret)
		l2n5pub := curve.Point.Generator().Mul(l2n5secret)
		l2n6pub := curve.Point.Generator().Mul(l2n6secret)
		l2n7pub := curve.Point.Generator().Mul(l2n7secret)
		l2n8pub := curve.Point.Generator().Mul(l2n8secret)
		l2n9pub := curve.Point.Generator().Mul(l2n9secret)

		_ = l2n4pub
		_ = l2n5pub
		_ = l2n6pub
		_ = l2n7pub
		_ = l2n8pub
		_ = l2n9pub

		l2pub := l2n1keyr1.commit[0].Add(l2n2keyr1.commit[0]).Add(l2n3keyr1.commit[0]).Add(l2n4keyr1.commit[0]).Add(l2n5keyr1.commit[0]).Add(l2n6keyr1.commit[0]).Add(l2n7keyr1.commit[0]).Add(l2n8keyr1.commit[0]).Add(l2n9keyr1.commit[0])

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
		l2n4pre := new(preprocess).Init(curvetype)
		l2n5pre := new(preprocess).Init(curvetype)
		l2n6pre := new(preprocess).Init(curvetype)
		l2n7pre := new(preprocess).Init(curvetype)
		l2n8pre := new(preprocess).Init(curvetype)
		l2n9pre := new(preprocess).Init(curvetype)

		_ = l2n4pre
		_ = l2n5pre
		_ = l2n6pre
		_ = l2n7pre
		_ = l2n8pre
		_ = l2n9pre
		//Sign (node1.1 node2.1 and node2.2 join the sign phase)
		message := "Hierarchical Threshold Sign"

		nonces := make([]curves.Point, 2*(thresh+1))
		nonces[0] = l1pre.noncecommit[0]
		nonces[1] = l1pre.noncecommit[1]
		nonces[2] = l2n1pre.noncecommit[0]
		nonces[3] = l2n1pre.noncecommit[1]
		nonces[4] = l2n2pre.noncecommit[0]
		nonces[5] = l2n2pre.noncecommit[1]
		nonces[6] = l2n3pre.noncecommit[0]
		nonces[7] = l2n3pre.noncecommit[1]

		// ro = hash(l,m,B)
		ro1 := hash1(message, 1, nonces, curvetype)
		ro2 := hash1(message, 2, nonces, curvetype)
		ro3 := hash1(message, 3, nonces, curvetype)
		ro4 := hash1(message, 4, nonces, curvetype)

		ro := make([]curves.Scalar, number)
		ro[0] = ro1
		ro[1] = ro2
		ro[2] = ro3
		ro[3] = ro4

		// each Participant derives group commitment
		R := groupcommit(ro, nonces, curvetype)

		// c = hash(R,Y,m)
		c := hash2(R, masterpub, message, curvetype)

		// level1 sign
		l1sign := l1pre.nonce[0].Add(l1pre.nonce[1].Mul(ro1)).Add((l1secret).Mul(c))

		// level2 signs
		list := make([]curves.Scalar, thresh)
		list[0] = curve.Scalar.New(1)
		list[1] = curve.Scalar.New(2)
		list[2] = curve.Scalar.New(3)
		lcoef := lagrangecoefficient(list, curve.Scalar.Zero(), curvetype)

		l2n1sign := l2n1pre.nonce[0].Add(l2n1pre.nonce[1].Mul(ro2)).Add(lcoef[0].Mul(l2n1secret).Mul(c))
		l2n2sign := l2n2pre.nonce[0].Add(l2n2pre.nonce[1].Mul(ro3)).Add(lcoef[1].Mul(l2n2secret).Mul(c))
		l2n3sign := l2n3pre.nonce[0].Add(l2n3pre.nonce[1].Mul(ro4)).Add(lcoef[2].Mul(l2n3secret).Mul(c))

		// Sign Aggregator SA performs following

		ro1 = hash1(message, 1, nonces, curvetype)
		ro2 = hash1(message, 2, nonces, curvetype)
		ro3 = hash1(message, 3, nonces, curvetype)
		ro4 = hash1(message, 4, nonces, curvetype)

		// R_i = D_i + ro_iE_i
		R1 := l1pre.noncecommit[0].Add(l1pre.noncecommit[1].Mul(ro1))
		R2 := l2n1pre.noncecommit[0].Add(l2n1pre.noncecommit[1].Mul(ro2))
		R3 := l2n2pre.noncecommit[0].Add(l2n2pre.noncecommit[1].Mul(ro3))
		R4 := l2n3pre.noncecommit[0].Add(l2n3pre.noncecommit[1].Mul(ro4))

		// bigR = R_1 + R_2 + R_3
		saR := R1.Add(R2).Add(R3).Add(R4)
		sac := hash2(saR, masterpub, message, curvetype)
		//fmt.Printf("%t", R.Equal(saR))
		//fmt.Printf("%t", equality(sac, c))

		//check pisign.G =? R_i + (c*lagrangei)Y_i

		/*
			fmt.Printf("%t ", curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0])))))
			fmt.Printf("%t ", curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1])))))
		*/

		curve.Point.Generator().Mul(l1sign).Equal(R1.Add(l1pub.Mul(sac)))
		curve.Point.Generator().Mul(l2n1sign).Equal(R2.Add(l2n1pub.Mul(sac.Mul(lcoef[0]))))
		curve.Point.Generator().Mul(l2n2sign).Equal(R3.Add(l2n2pub.Mul(sac.Mul(lcoef[1]))))
		curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2]))))
		// fmt.Printf("%t", curve.Point.Generator().Mul(l2n3sign).Equal(R4.Add(l2n3pub.Mul(sac.Mul(lcoef[2])))))
		sign := l1sign.Add(l2n1sign).Add(l2n2sign).Add(l2n3sign)

		_ = sign

	}
	duration := time.Since(start)
	fmt.Println("t4 m10 Our p256", duration/1000)

}
