package pqc_test

import (
	"testing"

	"github.com/cometbft/cometbft/crypto"
	pqc "github.com/cometbft/cometbft/crypto/dilithium"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndValidateDilithium(t *testing.T) {
	algorithm := "Dilithium2"
	pubKey, privKey, err := pqc.GenerateDilithiumKeyPair(algorithm)
	require.NoError(t, err)

	msg := crypto.CRandBytes(51)
	sig, err := privKey.DilithiumSign(algorithm, msg)
	require.NoError(t, err)

	assert.True(t, pubKey.DilithiumVerify(algorithm, msg, sig))

	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.DilithiumVerify(algorithm, msg, sig))
}
