package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/ldsec/crisp/CRISP_go/ring"
	"github.com/ldsec/crisp/CRISP_go/zkbpp"
	lr "github.com/tuneinsight/lattigo/ring"
	"github.com/tuneinsight/lattigo/utils"
)

func runCrisp() {
	// --- SETUP & PREPROCESSING (UNCHANGED) ---

	//input generation
	params := zkbpp.DefaultParamsCRISP()

	// Calculate the full modulus Q
	Q := new(big.Int).SetUint64(1)
	for _, qi := range params.Qi {
		Q.Mul(Q, new(big.Int).SetUint64(qi))
	}

	//crisp circuit
	crispRing := ring.NewRing(Q)
	crispCircuit := zkbpp.NewCircuit(crispRing)

	//prng
	utils.NewPRNG(nil)

	//gaussianSampler
	gaussianSamplerQ := crispCircuit.Rq.NewKYSampler(params.Sigma, int(6*params.Sigma))

	//keygen
	sk := crispCircuit.Rq.SampleTernaryNew(float64(1) / 3)

	//pk = [-a*s + e, a]
	pk := [2]*lr.Poly{crispCircuit.Rq.NewPoly(), crispCircuit.Rq.NewPoly()}
	e := gaussianSamplerQ.SampleNew()
	pk[1] = crispCircuit.Rq.NewUniformPoly()
	crispCircuit.Rq.MulCoeffs(sk, pk[1], pk[0])
	crispCircuit.Rq.Neg(pk[0], pk[0])
	crispCircuit.Rq.Add(pk[0], e, pk[0])

	//sample noises
	r0 := crispCircuit.Rq.NewPoly()
	e0 := crispCircuit.Rq.NewPoly()
	e1 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.SampleTernary(r0, 0.5)
	gaussianSamplerQ.Sample(e0)
	gaussianSamplerQ.Sample(e1)

	//bdop parameters
	n := 1
	k := 5

	//rc sampling
	rc := make([]*lr.Poly, k)
	for j := 0; j < len(rc); j++ {
		rc[j] = gaussianSamplerQ.SampleNew()
	}

	//public parameters
	a1 := make([][]*lr.Poly, n)
	a2 := make([][]*lr.Poly, 3)
	for i := 0; i < len(a1); i++ {
		a1[i] = make([]*lr.Poly, 4)
		for j := 0; j < len(a1[i]); j++ {
			a1[i][j] = crispCircuit.Rq.NewUniformPoly()
		}
	}
	for i := 0; i < len(a2); i++ {
		a2[i] = make([]*lr.Poly, 1)
		for j := 0; j < len(a2[i]); j++ {
			a2[i][j] = crispCircuit.Rq.NewUniformPoly()
		}
	}

	// --- INPUT DATA ---
	// Define the message (The Truth)
	message := []uint64{10, 20, 30, 40, 50}

	//input formatting
	crispInputs := []zkbpp.ZKBVar{}
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(r0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e1)...)
	for i := 0; i < k; i++ {
		crispInputs = append(crispInputs, crispCircuit.VarFromPoly(rc[i])...)
	}
	for i := 0; i < len(message); i++ {
		crispInputs = append(crispInputs, crispCircuit.VarUint64(message[i]))
	}

	//Circuit Definition
	crispCircuitDescription := func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {
		r0Var := crispCircuit.RqVarFromZqArray(input[0:crispCircuit.Rq.N])
		e0Var := crispCircuit.RqVarFromZqArray(input[crispCircuit.Rq.N : 2*crispCircuit.Rq.N])
		e1Var := crispCircuit.RqVarFromZqArray(input[2*crispCircuit.Rq.N : 3*crispCircuit.Rq.N])
		rcVar := make([]zkbpp.ZKBVar, k)
		for i := 0; i < k; i++ {
			rcVar[i] = crispCircuit.RqVarFromZqArray(input[uint64(3+i)*crispCircuit.Rq.N : uint64(4+i)*crispCircuit.Rq.N])
		}
		messageVar := input[uint64(3+k)*crispCircuit.Rq.N:]

		ct0, ct1, bdop1, bdop2, h := crispCircuit.MpcCRISP(r0Var, e0Var, e1Var, messageVar, rcVar, a1, a2, pk)

		output = make([]zkbpp.ZKBVar, 2+n+3+len(messageVar))
		output[0] = ct0
		output[1] = ct1
		for i := 0; i < n; i++ {
			output[2+i] = bdop1[i]
		}
		for i := 0; i < 3; i++ {
			output[2+n+i] = bdop2[i]
		}
		for i := 0; i < len(messageVar); i++ {
			output[2+n+3+i] = h[i]
		}
		return
	}
	crispCircuit.SetDescription(crispCircuitDescription)

	// --- EXECUTE PROOF ---
	fmt.Println("##################### PREPROCESS START ################")
	ctx, kkwP := zkbpp.Preprocess(crispCircuit, crispInputs, 229)
	opened, closed := zkbpp.PreprocessChallenge(229, 148)
	fmt.Println("###################### PREPROCESS END #################")
	fmt.Println()
	fmt.Println("##################### PROOF START ################")
	p, output := zkbpp.Prove(crispCircuit, crispInputs, ctx, opened, closed)
	fmt.Println("###################### PROOF END #################")
	fmt.Println()
	fmt.Println("##################### VERIF START ################")
	v := zkbpp.Verify(p, kkwP, opened, closed)
	fmt.Println("###################### VERIF END #################")
	fmt.Println("Proof is ", v)

	// Extract Ciphertexts
	ct0, ct1 := output[0], output[1]
	bdop1 := output[2]
	bdop2 := output[3:6]
	hash := output[6:]

	fmt.Println("Original message : ")
	fmt.Println(message)
	fmt.Println()

	// =========================================================================
	// 1. BASELINE CRISP RELEASE SYSTEM
	// =========================================================================
	fmt.Println("=== MODE 1: BASELINE CRISP RELEASE (Manual Noise Removal) ===")
	startBase := time.Now()

	fmt.Println("Decrypted output (Raw): ")
	pt := crispCircuit.CKKSDecrypt(ct0.RqValue, ct1.RqValue, sk)
	fmt.Println(crispCircuit.Rq.PolyToString(pt)[:len(message)])

	fmt.Println("Reconstructing Noises (Coefficient Domain)... ")
	noisePoly := crispCircuit.Rq.NewPoly()
	tmpNoise := crispCircuit.Rq.NewPoly()
	// Reconstruct the noise: e1*s + e*r0 + e0
	crispCircuit.Rq.MulCoeffs(e1, sk, noisePoly) // e1*s
	crispCircuit.Rq.MulCoeffs(e, r0, tmpNoise)   // e*r0
	crispCircuit.Rq.Add(tmpNoise, e0, tmpNoise)  // e*r0 + e0
	crispCircuit.Rq.Add(noisePoly, tmpNoise, noisePoly) // Total Noise

	fmt.Println("Subtracting Noises to release message... ")
	cleanPt := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Sub(pt, noisePoly, cleanPt)
	fmt.Println("Final Released Message: ")
	fmt.Println(crispCircuit.Rq.PolyToString(cleanPt)[:len(message)])

	elapsedBase := time.Since(startBase)
	fmt.Println("Baseline Release Time:", elapsedBase)
	fmt.Println()


	// =========================================================================
	// 2. NEW CVCP RELEASE SYSTEM
	// =========================================================================
	fmt.Println("=== MODE 2: CVCP RELEASE (Claimed-Value Consistency) ===")
	
	startCVCP := time.Now()
	
	// USER CLAIM
	K := []uint64{10, 20, 30, 40, 50} 

	// 1. Build Base Target (Coefficient Domain) = K + Noise
	baseTarget := crispCircuit.Rq.NewPoly()
	
	// Encode K
	polyK := crispCircuit.Rq.NewPoly()
	for j, qi := range crispCircuit.Rq.Modulus {
		for i := 0; i < len(K); i++ {
			polyK.Coeffs[j][i] = K[i] 
			if K[i] > qi {
				polyK.Coeffs[j][i] = K[i] % qi
			}
		}
	}
	crispCircuit.Rq.Add(polyK, noisePoly, baseTarget)

	// 2. FORMAT DISCOVERY (Auto-Detect Domain)
	// We try 4 combinations to see which one makes (ct0 - Target) decrypt to ~0.
	
	var bestTarget *lr.Poly
	minTotalDiff := ^uint64(0) // Max Uint64
	bestMode := ""

	// Options: 
	// 0: Raw
	// 1: NTT
	// 2: MForm
	// 3: MForm + NTT
	
	for mode := 0; mode < 4; mode++ {
		testTarget := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Copy(baseTarget, testTarget)
		
		desc := "Raw"
		if mode == 2 || mode == 3 {
			crispCircuit.Rq.MForm(testTarget, testTarget)
			desc = "MForm"
		}
		if mode == 1 || mode == 3 {
			crispCircuit.Rq.NTT(testTarget, testTarget)
			desc += "+NTT"
		}

		// Try Subtraction
		tmpD0 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Sub(ct0.RqValue, testTarget, tmpD0)
		
		// Decrypt
		decCheck := crispCircuit.CKKSDecrypt(tmpD0, ct1.RqValue, sk)
		
		// Check magnitude of first 5 coeffs
		var totalDiff uint64 = 0
		for i := 0; i < 5; i++ {
			val := decCheck.Coeffs[0][i]
			if val > (crispCircuit.Rq.Modulus[0] / 2) {
				val = crispCircuit.Rq.Modulus[0] - val
			}
			totalDiff += val
		}

		if totalDiff < minTotalDiff {
			minTotalDiff = totalDiff
			bestTarget = testTarget
			bestMode = desc
		}
	}

	fmt.Printf("Auto-Detected Ciphertext Domain: %s (Diff: %d)\n", bestMode, minTotalDiff)
	
	// 3. EXECUTE CVCP WITH CORRECT TARGET
	targetPoly := bestTarget

	// CVCP PARAMETERS
	repetitions := 5
	verified := true

	for t := 0; t < repetitions; t++ {
		r := uint64(rand.Intn(250) + 1) 
		
		// 1. Generate Mask c (Plaintext Domain)
		maskC := crispCircuit.Rq.NewUniformPoly()
		
		// 2. Prepare Mask for Addition (Transform to match X0 domain)
		maskEncoded := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Copy(maskC, maskEncoded)
		
		if bestMode == "MForm" || bestMode == "MForm+NTT" {
			crispCircuit.Rq.MForm(maskEncoded, maskEncoded)
		}
		if bestMode == "NTT" || bestMode == "MForm+NTT" {
			crispCircuit.Rq.NTT(maskEncoded, maskEncoded)
		}

		// 3. Challenge X
		D0 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Sub(ct0.RqValue, targetPoly, D0) // targetPoly is already in bestMode
		
		X0 := crispCircuit.Rq.NewPoly()
		X1 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.MulScalar(D0, r, X0)
		crispCircuit.Rq.MulScalar(ct1.RqValue, r, X1)
		
		crispCircuit.Rq.Add(X0, maskEncoded, X0)

		// 4. Response
		xDec := crispCircuit.CKKSDecrypt(X0, X1, sk)

		// 5. Verify
		// xDec should match maskC (Original Plaintext)
		for i := 0; i < len(K); i++ {
			valDec := xDec.Coeffs[0][i]
			valExp := maskC.Coeffs[0][i]
			qi := crispCircuit.Rq.Modulus[0]

			var diff uint64
			if valDec > valExp {
				diff = valDec - valExp
			} else {
				diff = valExp - valDec
			}
			if diff > (qi / 2) {
				diff = qi - diff
			}

			if diff > 100000 { 
				fmt.Printf("CVCP Verification FAILED at iter %d, index %d. Diff: %d\n", t, i, diff)
				verified = false
			}
		}
	}

	elapsedCVCP := time.Since(startCVCP)
	if verified {
		fmt.Println("CVCP Result: SUCCESS (User Claim Verified)")
	} else {
		fmt.Println("CVCP Result: FAILURE (Claim Rejected)")
	}
	fmt.Println("CVCP Release Time:", elapsedCVCP)

	fmt.Println()
	fmt.Println("SHA-256 (Unchanged):")
	for i := 0; i < len(hash); i++ {
		buf := make([]byte, 32)
		mpcSha := hash[i].Z2Value.FillBytes(buf)
		fmt.Println(hex.EncodeToString(mpcSha))
	}
	fmt.Println()

	fmt.Println("First coeffs of BDOP commitment : ")
	fmt.Println(crispCircuit.Rq.PolyToString(bdop1.RqValue)[0])
	for i := 0; i < len(bdop2); i++ {
		fmt.Println(crispCircuit.Rq.PolyToString(bdop2[i].RqValue)[0])
	}
}
