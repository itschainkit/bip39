package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// Entropy
func RandomBytes(bits int) ([]byte, error) {
	if bits < 128 || bits > 256 || bits%32 != 0 {
		errorMessage := "bip39.RandomBytes - Invalid entropy range. It should be between range 128-256 and be multiple of 32 bits."
		log.Fatal(errorMessage)
		return nil, errors.New(errorMessage)
	}
	bytes := make([]byte, bits/8)
	rand.Read(bytes)
	log.Printf("bip39.RandomBytes %d - %v\n", len(bytes), bytes)

	return bytes, nil
}

func Hex(bytes []byte) (string, error) {
	blength := len(bytes)
	if blength < 1 {
		return "", errors.New("bip39.Hex - input should have at least one byte")
	}

	hexBytes := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(hexBytes, bytes)

	result := fmt.Sprintf("%s", hexBytes)
	log.Printf("bip39.Hex %s\n", result)
	return result, nil
}

func ToBinaryString(bytess []byte) (string, error) {
	blength := len(bytess)
	if blength < 1 {
		return "", errors.New("bip39.ToBinaryString - input should have at least one byte")
	}

	sbinary := fmt.Sprintf("%08b", bytess)
	log.Printf("bip39.ToBinaryString %d - %s\n", len(sbinary), sbinary)
	return sbinary, nil
}

func Checksum(bitstring string) (string, error) {
	blength := len(bitstring)
	if blength < 128 {
		return "", errors.New("bit39.Checksum - input should have at least 128 bits")
	}

	bitsToTake := len(bitstring) / 32
	result := bitstring[:bitsToTake]
	log.Printf("bip39.Checksum %s\n", result)

	return result, nil
}

func BinarySeed(bitstring string) (string, error) {
	blength := len(bitstring)
	if blength < 128 {
		return "", errors.New("bit39.BinarySeed - input should have at least 128 bits")
	}
	checksum, _ := Checksum(bitstring)
	return (bitstring + checksum), nil
}

func WordsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New("bip39.WordsFromFile: Error to open file: " + err.Error())
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	result := make([]string, 2048) //all the files have 2048 words

	for i := 0; i < 2048; i++ {
		line, err := reader.ReadString('\n')
		result[i] = line
		if err != nil && err != io.EOF {
			return nil, errors.New("bip39.WordsFromFile: Error on read file: " + err.Error())
		}

		if err == io.EOF {
			break
		}
	}

	return result, nil
}

func Mnemonic(bits int, entropy string) []string {
	var randomNumbers []byte
	var err error

	if len(entropy) < 1 {
		randomNumbers, err = RandomBytes(bits)
	} else {
		randomNumbers = []byte(entropy)
	}

	if err != nil {
		panic(err.Error())
	}

	bitstring, err := ToBinaryString(randomNumbers)
	if err != nil {
		panic(err.Error())
	}

	binarySeed, err := BinarySeed(bitstring)
	if err != nil {
		panic(err.Error())
	}

	words, err := WordsFromFile("./english.txt")
	if err != nil {
		panic(err.Error())
	}

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
		wordIndex := ToDecimal(bitstring)
		word := words[wordIndex]
		chunks = append(chunks, word)
	}

	log.Printf("bip39.Mnemonic %s\n", chunks)

	return chunks
}

func ToDecimal(bitstring string) int {
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

func Seed(options map[string]string) (string, error) {
	if _, ok := options["mnemonic"]; !ok {
		return "", errors.New("bip39.Seed: mnemonic is a required option")
	}

	mnemonic := options["mnemonic"]
	salt := "mnemonic"

	if password, ok := options["password"]; ok {
		salt += password
	}

	//iteration = 2048
	//hash = sha512
	//key_length = 64 bytes / 512 bits
	key := pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New)
	keyHex := fmt.Sprintf("%x", key)

	log.Printf("bip29.Seed: Key - %s\n", keyHex)

	return keyHex, nil
}
