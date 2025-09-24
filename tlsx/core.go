package tlsx

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type TLSStream struct {
	KeyLabel     string
	Version      uint16
	CipherSuite  uint16
	ClientRandom []byte
	ServerRandom []byte
	MasterKey    []byte
	Seq          [8]byte
	serverConn   halfConn
	clientConn   halfConn
}

func NewTLSStream() *TLSStream {
	tlsStream := &TLSStream{
		Seq: [8]byte{0, 0, 0, 0, 0, 0, 0, 1},
	}

	return tlsStream
}

func establishKeys(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte) (cCipher, sCipher interface{}, cHash, sHash macFunction, err error) {
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(version, suite, masterSecret, clientRandom, serverRandom, suite.macLen, suite.keyLen, suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if suite.cipher != nil {
		clientCipher = suite.cipher(clientKey, clientIV, true)
		clientHash = suite.mac(version, clientMAC)
		serverCipher = suite.cipher(serverKey, serverIV, true)
		serverHash = suite.mac(version, serverMAC)
	} else {
		clientCipher = suite.aead(clientKey, clientIV)
		serverCipher = suite.aead(serverKey, serverIV)
	}

	return clientCipher, serverCipher, clientHash, serverHash, nil
}

func (t *TLSStream) EstablishConn() error {
	if t.Version == 0 || t.MasterKey == nil || t.ClientRandom == nil || t.ServerRandom == nil || t.CipherSuite == 0 {
		return errors.New("missing decrypt parameter")
	}

	cCipher, sCipher, cHash, sHash, err := establishKeys(t.Version, CipherSuiteByID(t.CipherSuite), t.MasterKey, t.ClientRandom, t.ServerRandom)

	if err != nil {
		return err
	}

	t.clientConn = halfConn{
		version: t.Version,
		cipher:  cCipher,
		mac:     cHash,
		seq:     t.Seq,
	}

	t.serverConn = halfConn{
		version: t.Version,
		cipher:  sCipher,
		mac:     sHash,
		seq:     t.Seq,
	}

	return nil
}

func (t *TLSStream) TLSDecrypt(record []byte, isRequest bool) (string, error) {

	var plaintext []byte
	var err error

	if isRequest {
		plaintext, _, err = t.clientConn.decrypt(record)
	} else {
		plaintext, _, err = t.serverConn.decrypt(record)
	}

	if err != nil {
		return "", err
	}

	t.incSeq()

	return string(plaintext), nil
}

// incSeq increments the sequence number.
func (t *TLSStream) incSeq() {
	for i := 7; i >= 0; i-- {
		t.Seq[i]++
		if t.Seq[i] != 0 {
			return
		}
	}
}

func (t *TLSStream) ShowHandShakeResult() {
	fmt.Printf("KeyLabel: %s \n", t.KeyLabel)
	fmt.Printf("Version: %x \n", t.Version)
	fmt.Printf("CipherSuite: %x \n", t.CipherSuite)
	fmt.Printf("ClientRandom: %s \n", hex.EncodeToString(t.ClientRandom))
	fmt.Printf("ServerRandom: %s \n", hex.EncodeToString(t.ServerRandom))
	fmt.Printf("Master Key: %s \n", hex.EncodeToString(t.MasterKey))
}
