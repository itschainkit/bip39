package main

import "testing"

func TestRandomBytes(t *testing.T) {
	r := RandomBytes()
	if r == nil {
		t.Error("Where is my number ?")
	}
}

func TestHex(t *testing.T) {
	r := Hex(RandomBytes())
	if r == "" {
		t.Error("Where is my hexa")
	}
}

func TestToBinaryString(t *testing.T) {
	r := ToBinaryString(RandomBytes())
	if r == "" {
		t.Error("Where is my Binary")
	}
}

func TestChecksum(t *testing.T) {
	bitstring := ToBinaryString(RandomBytes())
	r := Checksum(bitstring)
	if r == "" {
		t.Error("Where is my checksum")
	}
}

func TestBinarySeed(t *testing.T) {
	bitstring := ToBinaryString(RandomBytes())
	r := BinarySeed(bitstring)

	if r != bitstring+Checksum(bitstring) {
		t.Error("BinarySeed Unexpected")
	}
}

func TestWordsFromFile(t *testing.T) {
	result := WordsFromFile("./english.txt")
	if len(result) < 1 || len(result) != 2048 {
		t.Error("Error on taking words from File")
	}
}

func TestMnemonic(t *testing.T) {
	r := Mnemonic()
	if len(r) < 1 {
		t.Error("Where is my mnemonic")
	}
}

func TestToBase10(t *testing.T) {
	r := ToBase10("10010111101")
	if r != 1213 {
		t.Errorf("Something went wrong %d", r)
	}
}
