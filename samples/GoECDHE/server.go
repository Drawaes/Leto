package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	clientKey, err := hex.DecodeString("0447D49E92820985B45A100CE1A27727EB18F43B01E43F0425B0C894711E3C55EF9CCFE4C4C23CBC140732BF3DDF9D9FD3AD9F9222A2772EF3B0F8D94476A0ED21")
	if err != nil {
		panic(err)
	}

	curve := elliptic.P256()
    loops := 100000

	start := time.Now()
	for loop := 0; loop < loops; loop++ {
		privateKey, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}
		x1, y1 := elliptic.Unmarshal(curve, clientKey)
		xResult, yResult := curve.ScalarMult(x1, y1, privateKey)
		elliptic.Marshal(curve, xResult, yResult)
	}
	elapsed := time.Since(start)
	timePerOp := (float64(elapsed.Seconds()) * 1000.0) / float64(100000)
	fmt.Printf("%.4F", timePerOp)
}
