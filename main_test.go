package main

import "testing"

func TestRandomBytes(t *testing.T) {
	r, err := RandomBytes(128)
	if r == nil {
		t.Errorf("Should return a random number %s\n", err)
	}

	r, err = RandomBytes(192)
	if r == nil {
		t.Errorf("Should return a random number %s\n", err)
	}

	r, err = RandomBytes(256)
	if r == nil {
		t.Errorf("Should return a random number %s\n", err)
	}
}

func TestHex(t *testing.T) {
	b, _ := RandomBytes(128)
	r, err := Hex(b)
	if len(r) < 1 || err != nil {
		t.Error("bip39.Hex should return hex representation of bytes")
	}
}

func TestToBinaryString(t *testing.T) {
	b, _ := RandomBytes(128)
	r, err := ToBinaryString(b)
	if len(r) < 1 || err != nil {
		t.Error("bip39.ToBinaryString: should return a binary number as string representation")
	}
}

func TestChecksum(t *testing.T) {
	b, _ := RandomBytes(128)
	bitstring, _ := ToBinaryString(b)
	r, err := Checksum(bitstring)
	if len(r) < 1 || err != nil {
		t.Error("bip39.Checksum: should return the checksum")
	}
}

func TestBinarySeed(t *testing.T) {
	b, _ := RandomBytes(128)
	bitstring, _ := ToBinaryString(b)
	r, _ := BinarySeed(bitstring)
	checksum, _ := Checksum(bitstring)
	if r != bitstring+checksum {
		t.Error("bip39.BinarySeed Unexpected")
	}
}

func TestWordsFromFile(t *testing.T) {
	result, err := WordsFromFile("./english.txt")
	if err != nil || len(result) < 1 || len(result) != 2048 {
		t.Error("bip39.WordsFromFile: should read file content")
	}
}

func TestMnemonic(t *testing.T) {
	r := Mnemonic(128)
	if len(r) != 12 {
		t.Error("bip39.Mnemonic: should return a list of words")
	}
}

func TestToDecimal(t *testing.T) {
	r := ToDecimal("000000000")
	if r != 0 {
		t.Errorf("TestToDecimal - Invalid Decimal number %d", r)
	}
	r = ToDecimal("10010111101")
	if r != 1213 {
		t.Errorf("TestToDecimal - Invalid Decimal number %d", r)
	}
}
