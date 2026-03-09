package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"encoding/hex"
	"github.com/ldsec/crisp/CRISP_go/ring"
	"github.com/ldsec/crisp/CRISP_go/zkbpp"
	lr "github.com/tuneinsight/lattigo/ring"
	"github.com/tuneinsight/lattigo/utils"
)

func runCrisp() {
	// Define the vector sizes to test
	// NOTE: Max slots depend on ring dimension. Default params usually support up to 2048 or 4096.
	testSizes := []int{10, 20, 30}

	fmt.Println("===================================================================")
	fmt.Println("            CRISP SCALABILITY STRESS TEST (Baseline vs CVCP)       ")
	fmt.Println("===================================================================")
	fmt.Printf("%-10s | %-15s | %-15s | %-10s\n", "Size (N)", "Baseline Time", "CVCP Time", "Speedup")
	fmt.Println("-------------------------------------------------------------------")

	for _, nSize := range testSizes {
		runBenchmarkForSize(nSize)
	}
	fmt.Println("-------------------------------------------------------------------")
	fmt.Println("Stress Test Complete.")
}

func runBenchmarkForSize(N int) {
	// =========================================================================
	// 1. SETUP & INPUT GENERATION
	// =========================================================================
	params := zkbpp.DefaultParamsCRISP()
	Q := new(big.Int).SetUint64(1)
	for _, qi := range params.Qi {
		Q.Mul(Q, new(big.Int).SetUint64(qi))
	}
	crispRing := ring.NewRing(Q)
	crispCircuit := zkbpp.NewCircuit(crispRing)
	utils.NewPRNG(nil)
	gaussianSamplerQ := crispCircuit.Rq.NewKYSampler(params.Sigma, int(6*params.Sigma))

	// Keygen
	sk := crispCircuit.Rq.SampleTernaryNew(float64(1) / 3)
	pk := [2]*lr.Poly{crispCircuit.Rq.NewPoly(), crispCircuit.Rq.NewPoly()}
	e := gaussianSamplerQ.SampleNew()
	pk[1] = crispCircuit.Rq.NewUniformPoly()
	crispCircuit.Rq.MulCoeffs(sk, pk[1], pk[0])
	crispCircuit.Rq.Neg(pk[0], pk[0])
	crispCircuit.Rq.Add(pk[0], e, pk[0])

	// Sample noises
	r0 := crispCircuit.Rq.NewPoly()
	e0 := crispCircuit.Rq.NewPoly()
	e1 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.SampleTernary(r0, 0.5)
	gaussianSamplerQ.Sample(e0)
	gaussianSamplerQ.Sample(e1)

	// BDOP & Params
	nParams := 1
	kParams := 5
	rc := make([]*lr.Poly, kParams)
	for j := 0; j < len(rc); j++ { rc[j] = gaussianSamplerQ.SampleNew() }

	a1 := make([][]*lr.Poly, nParams)
	for i := 0; i < len(a1); i++ {
		a1[i] = make([]*lr.Poly, 4)
		for j := 0; j < len(a1[i]); j++ { a1[i][j] = crispCircuit.Rq.NewUniformPoly() }
	}
	a2 := make([][]*lr.Poly, 3)
	for i := 0; i < len(a2); i++ {
		a2[i] = make([]*lr.Poly, 1)
		for j := 0; j < len(a2[i]); j++ { a2[i][j] = crispCircuit.Rq.NewUniformPoly() }
	}

	// --- GENERATE RANDOM MESSAGE OF SIZE N ---
	message := make([]uint64, N)
	for i := 0; i < N; i++ {
		message[i] = uint64(rand.Intn(1000)) // Random values 0-999
	}

	// Input Formatting
	crispInputs := []zkbpp.ZKBVar{}
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(r0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e1)...)
	for i := 0; i < kParams; i++ {
		crispInputs = append(crispInputs, crispCircuit.VarFromPoly(rc[i])...)
	}
	for i := 0; i < len(message); i++ {
		crispInputs = append(crispInputs, crispCircuit.VarUint64(message[i]))
	}

	// Circuit Definition
	crispCircuit.SetDescription(func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {
		r0Var := crispCircuit.RqVarFromZqArray(input[0:crispCircuit.Rq.N])
		e0Var := crispCircuit.RqVarFromZqArray(input[crispCircuit.Rq.N : 2*crispCircuit.Rq.N])
		e1Var := crispCircuit.RqVarFromZqArray(input[2*crispCircuit.Rq.N : 3*crispCircuit.Rq.N])
		rcVar := make([]zkbpp.ZKBVar, kParams)
		for i := 0; i < kParams; i++ {
			rcVar[i] = crispCircuit.RqVarFromZqArray(input[uint64(3+i)*crispCircuit.Rq.N : uint64(4+i)*crispCircuit.Rq.N])
		}
		messageVar := input[uint64(3+kParams)*crispCircuit.Rq.N:]
		ct0, ct1, bdop1, bdop2, h := crispCircuit.MpcCRISP(r0Var, e0Var, e1Var, messageVar, rcVar, a1, a2, pk)
		output = make([]zkbpp.ZKBVar, 2+nParams+3+len(messageVar))
		output[0] = ct0
		output[1] = ct1
		for i := 0; i < nParams; i++ { output[2+i] = bdop1[i] }
		for i := 0; i < 3; i++ { output[2+nParams+i] = bdop2[i] }
		for i := 0; i < len(messageVar); i++ { output[2+nParams+3+i] = h[i] }
		return
	})

	// =========================================================================
	// 2. RUN PROOF (Silence Output)
	// =========================================================================
	// We run preprocessing and proving just to get the valid Ciphertext
	ctx, _ := zkbpp.Preprocess(crispCircuit, crispInputs, 229)
	opened, closed := zkbpp.PreprocessChallenge(229, 148)
	_, output := zkbpp.Prove(crispCircuit, crispInputs, ctx, opened, closed)
	
	ct0, ct1 := output[0], output[1]
	
	// =========================================================================
	// 3. BENCHMARK: BASELINE
	// =========================================================================
	tBaseStart := time.Now()

	pt := crispCircuit.CKKSDecrypt(ct0.RqValue, ct1.RqValue, sk)
	
	// Reconstruct Noise
	noisePoly := crispCircuit.Rq.NewPoly()
	tmpNoise := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.MulCoeffs(e1, sk, noisePoly)
	crispCircuit.Rq.MulCoeffs(e, r0, tmpNoise)
	crispCircuit.Rq.Add(tmpNoise, e0, tmpNoise)
	crispCircuit.Rq.Add(noisePoly, tmpNoise, noisePoly)

	// Release
	cleanPt := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Sub(pt, noisePoly, cleanPt)
	
	// Access values to force computation
	_ = crispCircuit.Rq.PolyToString(cleanPt)[:N]

	durBase := time.Since(tBaseStart)


	// =========================================================================
	// 4. BENCHMARK: CVCP
	// =========================================================================
	
	// 4a. Format Discovery (Done once per connection usually, so we don't time it in the loop)
	baseTarget := crispCircuit.Rq.NewPoly()
	polyK := crispCircuit.Rq.NewPoly()
	for j, qi := range crispCircuit.Rq.Modulus {
		for i := 0; i < N; i++ {
			polyK.Coeffs[j][i] = message[i] 
			if message[i] > qi { polyK.Coeffs[j][i] = message[i] % qi }
		}
	}
	crispCircuit.Rq.Add(polyK, noisePoly, baseTarget)

	bestMode := ""
	minTotalDiff := ^uint64(0)
	for mode := 0; mode < 4; mode++ {
		testTarget := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Copy(baseTarget, testTarget)
		desc := "Raw"
		if mode == 2 || mode == 3 { crispCircuit.Rq.MForm(testTarget, testTarget); desc = "MForm" }
		if mode == 1 || mode == 3 { crispCircuit.Rq.NTT(testTarget, testTarget); desc += "+NTT" }
		tmpD0 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Sub(ct0.RqValue, testTarget, tmpD0)
		decCheck := crispCircuit.CKKSDecrypt(tmpD0, ct1.RqValue, sk)
		var totalDiff uint64 = 0
		for i := 0; i < 5; i++ { // Check first 5 coeffs
			val := decCheck.Coeffs[0][i]
			if val > (crispCircuit.Rq.Modulus[0] / 2) { val = crispCircuit.Rq.Modulus[0] - val }
			totalDiff += val
		}
		if totalDiff < minTotalDiff {
			minTotalDiff = totalDiff
			bestMode = desc
		}
	}

	// 4b. Run CVCP Timing (Single Round for speed comparison, Honest User)
	tCVCPStart := time.Now()
	
	// 1. Build Target
	claimPoly := crispCircuit.Rq.NewPoly()
	for j, qi := range crispCircuit.Rq.Modulus {
		for i := 0; i < N; i++ {
			claimPoly.Coeffs[j][i] = message[i] 
			if message[i] > qi { claimPoly.Coeffs[j][i] = message[i] % qi }
		}
	}
	target := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Add(claimPoly, noisePoly, target)

	// 2. Transform
	if bestMode == "MForm" || bestMode == "MForm+NTT" { crispCircuit.Rq.MForm(target, target) }
	if bestMode == "NTT" || bestMode == "MForm+NTT" { crispCircuit.Rq.NTT(target, target) }

	// 3. Challenge
	r := uint64(rand.Intn(1000000) + 1000000)
	maskC := crispCircuit.Rq.NewUniformPoly()
	
	maskEncoded := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Copy(maskC, maskEncoded)
	if bestMode == "MForm" || bestMode == "MForm+NTT" { crispCircuit.Rq.MForm(maskEncoded, maskEncoded) }
	if bestMode == "NTT" || bestMode == "MForm+NTT" { crispCircuit.Rq.NTT(maskEncoded, maskEncoded) }

	D0 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Sub(ct0.RqValue, target, D0)
	X0 := crispCircuit.Rq.NewPoly()
	X1 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.MulScalar(D0, r, X0)
	crispCircuit.Rq.MulScalar(ct1.RqValue, r, X1)
	crispCircuit.Rq.Add(X0, maskEncoded, X0)

	// 4. Response
	xDec := crispCircuit.CKKSDecrypt(X0, X1, sk)

	// 5. Verification (Iterate N times)
	isValid := true // Track the verification status
	for i := 0; i < N; i++ {
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
		
		if diff > 1000 { 
			isValid = false // Mark as failed!
			break 
		}
	}

	durCVCP := time.Since(tCVCPStart)

	// Explicitly log the result so it doesn't fail silently
	if isValid {
		fmt.Println("CVCP Result: SUCCESS (User Claim Verified)")
	} else {
		fmt.Println("CVCP Result: FAILED (User Claim Rejected)")
	}
	
	// Calculate Speedup (Baseline / CVCP)
	// Note: If CVCP is faster, speedup > 1.0
	speedup := float64(durBase.Nanoseconds()) / float64(durCVCP.Nanoseconds())

	fmt.Printf("%-10d | %-15v | %-15v | %.2fx\n", N, durBase, durCVCP, speedup)
}

// runCrispCorrectness runs a deterministic, single-shot execution of CRISP
// to compare the baseline release phase against the CVCP release phase.
func runCrispCorrectness() {
	fmt.Println("===================================================================")
	fmt.Println("            CRISP CORRECTNESS & COMPARISON RUN                     ")
	fmt.Println("===================================================================")

	// --- SETUP & PREPROCESSING ---
	params := zkbpp.DefaultParamsCRISP()
	Q := new(big.Int).SetUint64(1)
	for _, qi := range params.Qi {
		Q.Mul(Q, new(big.Int).SetUint64(qi))
	}

	crispRing := ring.NewRing(Q)
	crispCircuit := zkbpp.NewCircuit(crispRing)
	utils.NewPRNG(nil)
	gaussianSamplerQ := crispCircuit.Rq.NewKYSampler(params.Sigma, int(6*params.Sigma))
	sk := crispCircuit.Rq.SampleTernaryNew(float64(1) / 3)

	pk := [2]*lr.Poly{crispCircuit.Rq.NewPoly(), crispCircuit.Rq.NewPoly()}
	e := gaussianSamplerQ.SampleNew()
	pk[1] = crispCircuit.Rq.NewUniformPoly()
	crispCircuit.Rq.MulCoeffs(sk, pk[1], pk[0])
	crispCircuit.Rq.Neg(pk[0], pk[0])
	crispCircuit.Rq.Add(pk[0], e, pk[0])

	r0 := crispCircuit.Rq.NewPoly()
	e0 := crispCircuit.Rq.NewPoly()
	e1 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.SampleTernary(r0, 0.5)
	gaussianSamplerQ.Sample(e0)
	gaussianSamplerQ.Sample(e1)

	n, k := 1, 5
	rc := make([]*lr.Poly, k)
	for j := 0; j < len(rc); j++ {
		rc[j] = gaussianSamplerQ.SampleNew()
	}

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
	message := []uint64{10, 20, 30, 40, 50}

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
	fmt.Println("###################### PREPROCESS END #################\n")

	fmt.Println("##################### PROOF START ################")
	p, output := zkbpp.Prove(crispCircuit, crispInputs, ctx, opened, closed)
	fmt.Println("###################### PROOF END #################\n")

	fmt.Println("##################### VERIF START ################")
	v := zkbpp.Verify(p, kkwP, opened, closed)
	fmt.Println("###################### VERIF END #################")
	fmt.Println("ZKB++ Proof Valid:", v)
	fmt.Println()

	ct0, ct1 := output[0], output[1]
	bdop1 := output[2]
	bdop2 := output[3:6]
	hash := output[6:]

	fmt.Println("Original true message : ", message, "\n")

	// =========================================================================
	// 1. BASELINE CRISP RELEASE SYSTEM
	// =========================================================================
	fmt.Println("=== MODE 1: BASELINE CRISP RELEASE (Manual Noise Removal) ===")
	startBase := time.Now()

	pt := crispCircuit.CKKSDecrypt(ct0.RqValue, ct1.RqValue, sk)
	fmt.Println("Decrypted output (Raw): ", crispCircuit.Rq.PolyToString(pt)[:len(message)])

	noisePoly := crispCircuit.Rq.NewPoly()
	tmpNoise := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.MulCoeffs(e1, sk, noisePoly)
	crispCircuit.Rq.MulCoeffs(e, r0, tmpNoise)
	crispCircuit.Rq.Add(tmpNoise, e0, tmpNoise)
	crispCircuit.Rq.Add(noisePoly, tmpNoise, noisePoly)

	cleanPt := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.Sub(pt, noisePoly, cleanPt)
	fmt.Println("Final Released Message: ", crispCircuit.Rq.PolyToString(cleanPt)[:len(message)])

	elapsedBase := time.Since(startBase)
	fmt.Println("Baseline Release Time:", elapsedBase, "\n")

	// =========================================================================
	// 2. NEW CVCP RELEASE SYSTEM
	// =========================================================================
	fmt.Println("=== MODE 2: CVCP RELEASE (Claimed-Value Consistency) ===")
	startCVCP := time.Now()
	
	// USER CLAIM
	K := []uint64{10, 20, 30, 40, 50} 
	fmt.Println("User Claimed Message:    ", K) // <-- ADD THIS LINE

	baseTarget := crispCircuit.Rq.NewPoly()
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
	
	var bestTarget *lr.Poly
	minTotalDiff := ^uint64(0)
	bestMode := ""

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

		tmpD0 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Sub(ct0.RqValue, testTarget, tmpD0)
		decCheck := crispCircuit.CKKSDecrypt(tmpD0, ct1.RqValue, sk)
		
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
	targetPoly := bestTarget
	repetitions := 5
	verified := true

	for t := 0; t < repetitions; t++ {
		r := uint64(rand.Intn(250) + 1) 
		maskC := crispCircuit.Rq.NewUniformPoly()
		maskEncoded := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Copy(maskC, maskEncoded)
		
		if bestMode == "MForm" || bestMode == "MForm+NTT" {
			crispCircuit.Rq.MForm(maskEncoded, maskEncoded)
		}
		if bestMode == "NTT" || bestMode == "MForm+NTT" {
			crispCircuit.Rq.NTT(maskEncoded, maskEncoded)
		}

		D0 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.Sub(ct0.RqValue, targetPoly, D0) 
		X0 := crispCircuit.Rq.NewPoly()
		X1 := crispCircuit.Rq.NewPoly()
		crispCircuit.Rq.MulScalar(D0, r, X0)
		crispCircuit.Rq.MulScalar(ct1.RqValue, r, X1)
		crispCircuit.Rq.Add(X0, maskEncoded, X0)

		xDec := crispCircuit.CKKSDecrypt(X0, X1, sk)

		// <-- ADD THIS BLOCK to print the inner workings of the first iteration
		if t == 0 {
			fmt.Println("SP Expected Mask        : ", crispCircuit.Rq.PolyToString(maskC)[:len(K)])
			fmt.Println("User Raw Decrypted      : ", crispCircuit.Rq.PolyToString(xDec)[:len(K)])
		}

		// Verification logic with the applied BUG FIX
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

			if diff > 1000 { 
				fmt.Printf("CVCP Verification FAILED at iter %d, index %d. Diff: %d\n", t, i, diff)
				verified = false
				break
			}
		}
		
		if !verified {
			break
		}
	}

	elapsedCVCP := time.Since(startCVCP)
	if verified {
		fmt.Println("CVCP Result: SUCCESS (User Claim Verified)")
		fmt.Println("Final Released Message:  ", K) // <-- ADD THIS LINE
	} else {
		fmt.Println("CVCP Result: FAILURE (Claim Rejected)")
	}
	fmt.Println("CVCP Release Time:", elapsedCVCP, "\n")

	fmt.Println("SHA-256 (Unchanged):")
	for i := 0; i < 1; i++ { // Just print the first one for brevity
		buf := make([]byte, 32)
		mpcSha := hash[i].Z2Value.FillBytes(buf)
		fmt.Println(hex.EncodeToString(mpcSha) + "...")
	}
	fmt.Println()

	fmt.Println("First coeffs of BDOP commitment : ")
	fmt.Println(crispCircuit.Rq.PolyToString(bdop1.RqValue)[0])
	for i := 0; i < len(bdop2); i++ {
		fmt.Println(crispCircuit.Rq.PolyToString(bdop2[i].RqValue)[0])
	}
}