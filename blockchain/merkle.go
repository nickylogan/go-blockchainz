package blockchain

import "crypto/sha256"

// MerkleTree only contains the root of the merkle tree, which is similar
// to a binary linked tree.
type MerkleTree struct {
	RootNode *MerkleNode
}

// MerkleNode represents a node in a MerkleTree
type MerkleNode struct {
	// Left points to the first child of this node
	Left  *MerkleNode
	// Right points to the second child of this node
	Right *MerkleNode
	// Data stores the actual data of this node
	Data  []byte
}

// NewMerkleNode creates a new merkle node, based on its children and data
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		node.Data = hash[:]
	}

	node.Left = left
	node.Right = right

	return &node
}

// NewMerkleTree creates a new merkle tree based on slices of data
func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode

	if len(data)%2 != 0 {
		data = append(data, data[len(data)-1])
	}

	for _, dat := range data {
		node := NewMerkleNode(nil, nil, dat)
		nodes = append(nodes, *node)
	}

	for i := 0; i < len(data)/2; i++ {
		var level []MerkleNode

		for j := 0; j < len(nodes); j += 2 {
			node := NewMerkleNode(&nodes[j], &nodes[j+1], nil)
			level = append(level, *node)
		}

		nodes = level
	}

	tree := MerkleTree{&nodes[0]}

	return &tree
}
