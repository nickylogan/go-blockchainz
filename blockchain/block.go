package blockchain

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"
)

// Block represents a block inside a blockchain
type Block struct {
	// Timestamp uniquely identifies each block by the time it's created
	Timestamp int64
	// Hash is the message digest of the block, uniquely identifying each data
	Hash []byte
	// Transactions is a slice of transactions, which is the data stored in each block
	Transactions []*Transaction
	// PrevHash points to the hash of the previous block. This connects each block,
	// into a blockchain
	PrevHash []byte
	// Nonce stores the number that is required for the proof of work
	Nonce int
	// Height represents the block's index in the blockchain
	Height int
}

// HashTransactions builds a merkle tree out of all the transactions,
// and its root, will be the hash of all transactions
func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte

	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.Serialize())
	}
	tree := NewMerkleTree(txHashes)

	return tree.RootNode.Data
}

// CreateBlock takes the required data for each block: a list of transactions,
// the hash of the previous block, along with it's supposed height. It initializes the
// other fields of the block, according to the given arguments
func CreateBlock(txs []*Transaction, prevHash []byte, height int) *Block {
	block := &Block{time.Now().Unix(), []byte{}, txs, prevHash, 0, height}
	pow := NewProof(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

// Genesis creates a genesis block, given a coinbase transaction
func Genesis(coinbase *Transaction) *Block {
	return CreateBlock([]*Transaction{coinbase}, []byte{}, 0)
}

// Serialize returns the serialized byte representation of the block
func (b *Block) Serialize() []byte {
	var res bytes.Buffer
	encoder := gob.NewEncoder(&res)

	err := encoder.Encode(b)

	Handle(err)

	return res.Bytes()
}

// Deserialize takes a stream of bytes, and returns the deserialized block data
func Deserialize(data []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(data))

	err := decoder.Decode(&block)

	Handle(err)

	return &block
}

// Handle handles errors that might arise during the program execution
func Handle(err error) {
	if err != nil {
		log.Panic(err)
	}
}
