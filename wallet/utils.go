package wallet

import (
	"log"

	"github.com/mr-tron/base58"
)

// Base58Encode encodes a slice of byte into its base 58 representation
func Base58Encode(input []byte) []byte {
	encode := base58.Encode(input)

	return []byte(encode)
}

// Base58Decode decodes a base 58 representation into a byte slice
func Base58Decode(input []byte) []byte {
	decode, err := base58.Decode(string(input[:]))
	if err != nil {
		log.Panic(err)
	}

	return decode
}