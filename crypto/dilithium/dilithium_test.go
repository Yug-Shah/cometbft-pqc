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

func TestBatchSafe(t *testing.T) {
	v := pqc.NewBatchVerifier()

	algorithm := "Dilithium2"

	for i := 0; i <= 38; i++ {
		pub, priv, err := pqc.GenerateDilithiumKeyPair(algorithm)
		require.NoError(t, err)

		var msg []byte
		if i%2 == 0 {
			msg = []byte("easter")
		} else {
			msg = []byte("egg")
		}

		sig, err := priv.DilithiumSign(algorithm, msg)
		require.NoError(t, err)

		err = v.Add(pub, msg, sig, algorithm)
		require.NoError(t, err)
	}

	// Verify all entries in the batch
	for _, entry := range v.Verifications {
		ok := v.Verify(entry.Algorithm, entry.Message, entry.Signature, entry.PubKey.Key)

		require.True(t, ok, "Batch verification failed for one or more signatures")
	}
}
