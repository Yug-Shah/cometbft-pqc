package pqc

import (
	"crypto/sha512"
	"errors"
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

//import "C"

type DilithiumPrivateKey struct {
	Key []byte
}

type DilithiumPublicKey struct {
	Key []byte
}

var SupportedPQCSchemes = []string{"Dilithium2", "Dilithium3", "Dilithium5"}

// GenerateKeyPair generates a new Dilithium key pair using liboqs-go
func GenerateDilithiumKeyPair(algorithm string) (DilithiumPublicKey, DilithiumPrivateKey, error) {
	if !isSupportedPQC(algorithm) {
		return DilithiumPublicKey{}, DilithiumPrivateKey{}, errors.New("unsupported PQC algorithm")
	}

	signer := oqs.Signature{}

	// Initialize Dilithium
	err := signer.Init(algorithm, nil)
	if err != nil {
		log.Fatalf("Failed to initialize Dilithium: %v", err)
	}

	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return DilithiumPublicKey{}, DilithiumPrivateKey{}, err
	}

	return DilithiumPublicKey{Key: pubKey}, DilithiumPrivateKey{Key: signer.ExportSecretKey()}, nil
}

// Sign signs a message using the Dilithium private key
func (privKey DilithiumPrivateKey) DilithiumSign(algorithm string, message []byte) ([]byte, error) {
	signer := oqs.Signature{}
	defer signer.Clean()

	err := signer.Init(algorithm, privKey.Key)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(message)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// Address is the SHA512-20 of the raw pubkey bytes.
func (pubKey DilithiumPublicKey) Address() []byte {
	hash := sha512.Sum512(pubKey.Key)

	// Return the first 20 bytes of the hash
	return hash[:20]
}

// Verify verifies a signature using the Dilithium public key
func (pubKey DilithiumPublicKey) DilithiumVerify(algorithm string, message, signature []byte) bool {
	verifier := oqs.Signature{}
	defer verifier.Clean()

	err := verifier.Init(algorithm, nil)
	if err != nil {
		return false
	}

	valid, err := verifier.Verify(message, signature, pubKey.Key)
	if err != nil {
		return false
	}

	return valid
}

// Check if the algorithm is supported
func isSupportedPQC(algorithm string) bool {
	for _, algo := range SupportedPQCSchemes {
		if algo == algorithm {
			return true
		}
	}
	return false
}
