package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"
)

func main() {
	repeatedValue := make([]byte, 1)
	repeatedValue[0] = 77
	input := make([]byte, 64*1024)
	iv := bytes.Repeat(repeatedValue, 12)
	key := bytes.Repeat(repeatedValue, 16)
	totalLoops := (1024 * 1024 * 1024 * 10) / len(input)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error)
	}
	start := time.Now()
	for loop := 0; loop < totalLoops; loop++ {
		output := aesgcm.Seal(nil, iv, input, nil)
		if input[0] == output[0] {
			panic(input[0])
		}
	}
	elapsed := time.Since(start)
	bytesPerSec := (float64(totalLoops*len(input)) / (elapsed.Seconds())) / (1024 * 1024)
	fmt.Printf("%.2F", bytesPerSec)

}
