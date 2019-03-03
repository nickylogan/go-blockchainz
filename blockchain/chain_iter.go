package blockchain

import "github.com/dgraph-io/badger"

// Iterator represents an iterator for a blockchain
type Iterator struct {
	CurrentHash []byte
	Database    *badger.DB
}

// Begin creates an iterator, pointing to the last block of the chain
func (chain *BlockChain) Begin() *Iterator {
	iter := &Iterator{chain.LastHash, chain.Database}

	return iter
}

// Next moves the current iterator to the previous block
func (iter *Iterator) Next() *Block {
	var block *Block

	err := iter.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get(iter.CurrentHash)
		Handle(err)
		encodedBlock, err := item.Value()
		block = Deserialize(encodedBlock)

		return err
	})
	Handle(err)

	iter.CurrentHash = block.PrevHash

	return block
}
