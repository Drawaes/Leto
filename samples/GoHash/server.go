package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"
)

func main() {
	repeatedValue := make([]byte, 1)
	repeatedValue[0] = 7
	input := bytes.Repeat(repeatedValue, 8*1024)
	outerloops := 100000
	innerloops := 20
	totalbytes := outerloops * innerloops * len(input)

	start := time.Now()
	for outerloop := 0; outerloop < outerloops; outerloop++ {
		hash := sha256.New()
		for innerloop := 0; innerloop < innerloops; innerloop++ {
			hash.Write(input)
		}
		hash.Sum(nil)
	}
	elapsed := time.Since(start)
	bytesPerSec := (float64(totalbytes) / float64(elapsed.Seconds())) / (1024.0 * 1024.0)
	fmt.Printf("%.2F", bytesPerSec)

}
