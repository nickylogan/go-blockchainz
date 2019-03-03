package blockchain

import (
	"bytes"
	"encoding/gob"

	"github.com/nickylogan/go-blockchainz/wallet"
)

// TxOutput represents a transaction output, containing a number of tokens
// to be sent, and the public key that has the rights to this output
type TxOutput struct {
	Value      int
	PubKeyHash []byte
}

// TxOutputs stores a list of TxOutput
type TxOutputs struct {
	Outputs []TxOutput
}

// TxInput is a reference to a transaction output
type TxInput struct {
	// ID is the transaction ID where its output is referenced
	ID []byte
	// Out is the index of the output inside the referenced transaction
	Out int
	// Signature authenticates the wallet that creates this
	// transaction input
	Signature []byte
	// PubKey is used to verify the given signature
	PubKey []byte
}

// UsesKey checks whether a given transaction input signature uses a given
// public key hash
func (in *TxInput) UsesKey(pubKeyHash []byte) bool {
	lockingHash := wallet.PublicKeyHash(in.PubKey)

	return bytes.Compare(lockingHash, pubKeyHash) == 0
}

// Lock locks a transaction output with the address of the wallet
func (out *TxOutput) Lock(address []byte) {
	pubKeyHash := wallet.Base58Decode(address)
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-wallet.ChecksumLength]
	out.PubKeyHash = pubKeyHash
}

// IsLockedWithKey checks whether the transaction output is locked
// with the given public key hash
func (out *TxOutput) IsLockedWithKey(pubKeyHash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubKeyHash) == 0
}

// NewTXOutput creates a new transaction output with a given value
// and destination address
func NewTXOutput(value int, address string) *TxOutput {
	txo := &TxOutput{value, nil}
	txo.Lock([]byte(address))

	return txo
}

// Serialize dumps a list of transaction outputs into a byte slice
func (outs TxOutputs) Serialize() []byte {
	var buffer bytes.Buffer
	encode := gob.NewEncoder(&buffer)
	err := encode.Encode(outs)
	Handle(err)
	return buffer.Bytes()
}

// DeserializeOutputs attempts to build a TxOutputs object
// by loading a slice of bytes
func DeserializeOutputs(data []byte) TxOutputs {
	var outputs TxOutputs
	decode := gob.NewDecoder(bytes.NewReader(data))
	err := decode.Decode(&outputs)
	Handle(err)
	return outputs
}
