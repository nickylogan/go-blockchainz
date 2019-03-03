package blockchain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/nickylogan/go-blockchainz/wallet"
)

// Transaction represents the data stored inside a block of a blockchain.
type Transaction struct {
	// ID represents the transaction ID being stored
	ID []byte
	// Inputs represents the token inputs being spent for the transaction
	Inputs []TxInput
	// Outputs represents the result of the transaction, which is the number of
	// tokens received for each wallet address (spent tokens and change tokens)
	Outputs []TxOutput
}

// Hash gives the hash of a transaction
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}

	hash = sha256.Sum256(txCopy.Serialize())

	return hash[:]
}

// Serialize dumps the transaction object into a byte slice
func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

// DeserializeTransaction attempts to build a Transaction object
// by loading a slice of bytes
func DeserializeTransaction(data []byte) Transaction {
	var transaction Transaction

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction)
	Handle(err)
	return transaction
}

// CoinbaseTx creates a coinbase transaction, intended to be send to
// 'to' address.
func CoinbaseTx(to, data string) *Transaction {
	if data == "" {
		randData := make([]byte, 24)
		_, err := rand.Read(randData)
		Handle(err)
		data = fmt.Sprintf("%x", randData)
	}

	// Since this transaction's inputs do not refer to any transaction output,
	// we simply initialize a meaningless transaction input
	txin := TxInput{[]byte{}, -1, nil, []byte(data)}
	// This output is the reward, which tokens are sent to the 'to' address
	txout := NewTXOutput(20, to)

	tx := Transaction{nil, []TxInput{txin}, []TxOutput{*txout}}
	tx.ID = tx.Hash()

	return &tx
}

// NewTransaction attempts to create a new transaction, such that wallet 'w' sends an 'amount' of tokens
// to the 'to' address, where 'UTXO' is the set of all unspent transaction outputs in the blockchain
func NewTransaction(w *wallet.Wallet, to string, amount int, UTXO *UTXOSet) *Transaction {
	var inputs []TxInput
	var outputs []TxOutput

	// Acquire all outputs that are spendable from wallet w, with the given amount
	pubKeyHash := wallet.PublicKeyHash(w.PublicKey)
	acc, validOutputs := UTXO.FindSpendableOutputs(pubKeyHash, amount)

	// Check if the accumulated unspent outputs is sufficient
	if acc < amount {
		log.Panic("Error: not enough funds")
	}

	// For each unspent output, we create a transaction input referencing it
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		Handle(err)

		for _, out := range outs {
			input := TxInput{txID, out, nil, w.PublicKey}
			inputs = append(inputs, input)
		}
	}

	from := fmt.Sprintf("%s", w.Address())

	// We create the transaction output, which is the one sent to the 'to' address
	outputs = append(outputs, *NewTXOutput(amount, to))

	// If the accumulated input is larger than the amount to be sent, we create a 'change'
	// transaction output, which is sent back to the original sender
	if acc > amount {
		outputs = append(outputs, *NewTXOutput(acc-amount, from))
	}

	tx := Transaction{nil, inputs, outputs}
	tx.ID = tx.Hash()

	// Finally, the sender signs the created transaction
	UTXO.Blockchain.SignTransaction(&tx, w.PrivateKey)

	return &tx
}

// IsCoinbase checks whether a given transaction is a coinbase transaction
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && len(tx.Inputs[0].ID) == 0 && tx.Inputs[0].Out == -1
}

// Sign creates the signature of a transaction with a given private key and previous transactions
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction) {
	if tx.IsCoinbase() {
		return
	}

	// Check whether transactions that the input refers to, exist
	for _, in := range tx.Inputs {
		if prevTXs[hex.EncodeToString(in.ID)].ID == nil {
			log.Panic("ERROR: Previous transaction is not correct")
		}
	}

	txCopy := tx.TrimmedCopy()

	// Create signature based on a modified copy of transaction
	for inId, in := range txCopy.Inputs {
		// Get the previous transaction that the input refers to
		prevTX := prevTXs[hex.EncodeToString(in.ID)]
		// Strip off the transaction input's signature
		txCopy.Inputs[inId].Signature = nil
		// Temporarily set the input's public key to be the same as the output it refers to
		txCopy.Inputs[inId].PubKey = prevTX.Outputs[in.Out].PubKeyHash
		
		dataToSign := fmt.Sprintf("%x\n", txCopy)

		r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(dataToSign))
		Handle(err)
		signature := append(r.Bytes(), s.Bytes()...)

		// Sign the transaction
		tx.Inputs[inId].Signature = signature
		// Reset the input's public key to nil
		txCopy.Inputs[inId].PubKey = nil
	}
}

// Verify verifies the validity of a transaction
func (tx *Transaction) Verify(prevTXs map[string]Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}

	// Ensure that previous transactions the inputs reference exist
	for _, in := range tx.Inputs {
		if prevTXs[hex.EncodeToString(in.ID)].ID == nil {
			log.Panic("Previous transaction not correct")
		}
	}

	txCopy := tx.TrimmedCopy()
	curve := elliptic.P256()

	// For each input, check its signature against from where its derived
	// (trimmed transaction copy)
	for inId, in := range tx.Inputs {
		prevTx := prevTXs[hex.EncodeToString(in.ID)]
		txCopy.Inputs[inId].Signature = nil
		txCopy.Inputs[inId].PubKey = prevTx.Outputs[in.Out].PubKeyHash

		r := big.Int{}
		s := big.Int{}

		sigLen := len(in.Signature)
		r.SetBytes(in.Signature[:(sigLen / 2)])
		s.SetBytes(in.Signature[(sigLen / 2):])

		x := big.Int{}
		y := big.Int{}
		keyLen := len(in.PubKey)
		x.SetBytes(in.PubKey[:(keyLen / 2)])
		y.SetBytes(in.PubKey[(keyLen / 2):])

		dataToVerify := fmt.Sprintf("%x\n", txCopy)

		rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
		if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), &r, &s) == false {
			return false
		}
		txCopy.Inputs[inId].PubKey = nil
	}

	return true
}

// TrimmedCopy returns a copy of a transaction, while stripping off the signature
// and public key of its inputs
func (tx *Transaction) TrimmedCopy() Transaction {
	var inputs []TxInput
	var outputs []TxOutput

	for _, in := range tx.Inputs {
		inputs = append(inputs, TxInput{in.ID, in.Out, nil, nil})
	}

	for _, out := range tx.Outputs {
		outputs = append(outputs, TxOutput{out.Value, out.PubKeyHash})
	}

	txCopy := Transaction{tx.ID, inputs, outputs}

	return txCopy
}

// String enables Transaction to implement the Stringer interface
func (tx Transaction) String() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("--- Transaction %x:", tx.ID))
	for i, input := range tx.Inputs {
		lines = append(lines, fmt.Sprintf("     Input %d:", i))
		lines = append(lines, fmt.Sprintf("       TXID:      %x", input.ID))
		lines = append(lines, fmt.Sprintf("       Out:       %d", input.Out))
		lines = append(lines, fmt.Sprintf("       Signature: %x", input.Signature))
		lines = append(lines, fmt.Sprintf("       PubKey:    %x", input.PubKey))
	}

	for i, output := range tx.Outputs {
		lines = append(lines, fmt.Sprintf("     Output %d:", i))
		lines = append(lines, fmt.Sprintf("       Value:  %d", output.Value))
		lines = append(lines, fmt.Sprintf("       Script: %x", output.PubKeyHash))
	}

	return strings.Join(lines, "\n")
}
