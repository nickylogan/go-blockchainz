package wallet

import (
	"bytes"
	"crypto/elliptic"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const walletFile = "./tmp/wallets_%s.data"

// Wallets stores a map of nodeID to Wallet
type Wallets struct {
	Wallets map[string]*Wallet
}

// CreateWallets loads a wallet file on a given node
func CreateWallets(nodeID string) (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFile(nodeID)

	return &wallets, err
}

// AddWallet creates a wallet into a wallet set, and
// returns its address
func (ws *Wallets) AddWallet() string {
	wallet := MakeWallet()
	address := fmt.Sprintf("%s", wallet.Address())

	ws.Wallets[address] = wallet

	return address
}

// GetAllAddresses returns all addresses contained in a wallet set
func (ws *Wallets) GetAllAddresses() []string {
	var addresses []string

	for address := range ws.Wallets {
		addresses = append(addresses, address)
	}

	return addresses
}

// GetWallet returns a wallet instance based on its address
func (ws Wallets) GetWallet(address string) Wallet {
	return *ws.Wallets[address]
}

// LoadFile loads a wallet file, and deserializes its contents
// into the wallets instance
func (ws *Wallets) LoadFile(nodeID string) error {
	walletFile := fmt.Sprintf(walletFile, nodeID)
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err
	}

	var wallets Wallets

	fileContent, err := ioutil.ReadFile(walletFile)
	if err != nil {
		return err
	}

	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))
	err = decoder.Decode(&wallets)
	if err != nil {
		return err
	}

	ws.Wallets = wallets.Wallets

	return nil
}

// SaveFile dumps the contents of the instance into a binary file
func (ws *Wallets) SaveFile(nodeID string) {
	var content bytes.Buffer
	walletFile := fmt.Sprintf(walletFile, nodeID)

	gob.Register(elliptic.P256())

	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(ws)
	if err != nil {
		log.Panic(err)
	}

	err = ioutil.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}
