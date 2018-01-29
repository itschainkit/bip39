package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

//Entropy default length
const bits = 128

// Entropy
func RandomBytes() []byte {
	bytes := make([]byte, bits/8)
	rand.Read(bytes)
	log.Printf("bip39.RandomBytes %d - %v\n", len(bytes), bytes)
	return bytes
}

func Hex(bytes []byte) string {
	hexBytes := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(hexBytes, bytes)

	result := fmt.Sprintf("%s", hexBytes)
	log.Printf("bip39.Hex %s\n", result)
	return result
}

func ToBinaryString(bytess []byte) string {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, bytess)

	var sbinary string
	for _, byte := range buffer.Bytes() {
		sbinary += fmt.Sprintf("%08b", byte)
	}

	log.Printf("bip39.ToBinaryString %d - %s\n", len(sbinary), sbinary)
	return sbinary
}

func Checksum(bitstring string) string {
	bitsToTake := bits / 32
	result := bitstring[:bitsToTake]
	log.Printf("bip39.Checksum %s\n", result)

	return result
}

func BinarySeed(bitstring string) string {
	return bitstring + Checksum(bitstring)
}

func WordsFromFile(filePath string) []string {
	file, _ := os.Open(filePath)
	defer file.Close()

	reader := bufio.NewReader(file)
	result := make([]string, 2048) //TODO: check how to take off this fixed value

	for i := 0; i < 2048; i++ {
		line, err := reader.ReadString('\n')
		result[i] = line
		if err != nil || err == io.EOF {
			break
		}
	}

	return result
}

//TODO: put it flexlible to accept bits and entropy as argument
func Mnemonic() []string {
	bitstring := ToBinaryString(RandomBytes())
	binarySeed := BinarySeed(bitstring)
	words := WordsFromFile("./english.txt")
	chunkSize := 11

	var chunks []string
	runes := []rune(binarySeed)

	if len(runes) == 0 {
		return []string{binarySeed}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		bitstring := string(runes[i:nn])
		wordIndex := ToBase10(bitstring)
		word := words[wordIndex]
		chunks = append(chunks, word)
	}

	fmt.Printf("bip39.Mnemonic %s\n", chunks)

	return chunks
}

func ToBase10(bitstring string) int {
	result := 0
	power := 1
	for i := len(bitstring) - 1; i >= 0; i-- {
		if bitstring[i] == '1' {
			result += power
		}
		power *= 2
	}

	return result
}
