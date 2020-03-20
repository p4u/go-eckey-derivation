package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	sign "gitlab.com/vocdoni/go-dvote/crypto/signature"
)

/*
Experiment:

Three actors: Signer, Verifyer, Observer

1. The PubKey of Signer is only known by Verifyer (not by Observer)
2. We want to keep the PubKey of Signer hidden for Observer (to preserve his identity)
3. But Verifyer wants to publish an open challenge which can only be solved by Signer (he wants to know Signer is legit)
4. There cannot be direct/secret interaction between Signer and Verifier
5. For such task Verifyer publish a Number (N), which will be used to derivate a new pair of pub/priv keys
6. Signer must derivate the new PrivateKey using its own PrivateKey and the number N
7. Verifyer must derivate the PublicKey of Signer using the original PublicKey and the number N
8. Obersver do not know the public key of Verifier so, even knowing N he cannot derivate the new public key

PubKey = PrivKey * G
N = anArbitraryNumber
PrivKey2 = Privkey + N
PubKey2 = PubKey + N

Can we sign with Privkey2 and verify with Pubkey2?

Output example:

    On curve: true
    Original:       562981509c13ff5f52f5637fc388a304ea169ea8dafba5de7691ad96ef09a0a3 0246a458b1beedc9cddecb010ae48c816291cbe3b24025af8b1a3f087b442aa645
    New:            566eedb5ff8868cec11595aff4c1d3381b48bf0b475d084ad7f419f851760205 02396a12dee1fab9c600fd626fb789560ee078c0dd6d80887fd2ce6b0a9458f9b0
    New signature: b68246b6a1f91f99f9d520278074ad027b53e93ed5ca91601ea7880f461d2edf34ba248a635724b93470ad52618814885d41c002b930cc057a620f14578b575300
    Verification: true
*/

func main() {
	var s sign.SignKeys

	// generate new keys, s is owned by Signer
	err := s.Generate()
	if err != nil {
		panic(err)
	}

	// get the curve
	ec := s.Public.Curve

	// save the current pub/priv keys
	pub, priv := s.HexString()

	// get the bigInt which will be used to modify the key (16 bytes / 128 bits)
	// this number is shared so it's visible to anyone (including observer)
	n := new(big.Int).SetBytes([]byte("Election 2019031"))

	// add it to the current key, so now we have a new private key (currentPrivKey + n)
	s.Private.D.Add(s.Private.D, n)

	// save the new private key in hex format
	_, newPriv := s.HexString()

	// lets generate the new Public Key, but without using the Private Key
	// note that s2 do not know, at any moment, the value of PrivKey, s2 is owned by the Verifier
	s2 := new(sign.SignKeys)
	s2.Public = new(ecdsa.PublicKey)

	// get the x,y points of n
	new_x, new_y := ec.ScalarBaseMult(n.Bytes())

	// add these two new points to the ones of the original pubKey
	x, y := ec.Add(s.Public.X, s.Public.Y, new_x, new_y)

	// and set these points as public key for s2
	s2.Public.X = x
	s2.Public.Y = y

	// check if they are in the curve
	fmt.Printf("On curve: %t\n", ec.IsOnCurve(x, y))

	// get the new priv/pub keys as hexStrings and print them
	newPub, _ := s2.HexString()
	fmt.Printf("Original:\t%s %s\nNew:\t\t%s %s\n", priv, pub, newPriv, newPub)

	// let's try to sign using the private key (note we use s for signing)
	signature, err := s.Sign("Hello world")
	if err != nil {
		panic(err)
	}

	// and verify using the public key (not we use s2 for verifying)
	fmt.Printf("New signature: %s\n", signature)
	v, err := sign.Verify("Hello world", signature, newPub)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Verification: %t\n", v)
}
