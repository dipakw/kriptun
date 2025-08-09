package auth

import (
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

func Server(clientConn net.Conn, args *ServerOpts) *Auth {
	res := &Auth{}

	if args.Bits != 768 && args.Bits != 1024 {
		return res.re(&Err{
			reason: "invalid bits",
			err:    fmt.Errorf("received: %d, must be 768 or 1024", args.Bits),
		})
	}

	// Step 1: Generate private key.
	var privkey any
	var err error

	if args.Bits == 768 {
		privkey, err = mlkem.GenerateKey768()
	} else {
		privkey, err = mlkem.GenerateKey1024()
	}

	if err != nil {
		return res.re(&Err{
			reason: "failed to generate a private key",
			err:    err,
		})
	}

	// Step 2: Send public key to the client.
	var pubkeyb []byte

	if args.Bits == 768 {
		pubkeyb = privkey.(*mlkem.DecapsulationKey768).EncapsulationKey().Bytes()
	} else {
		pubkeyb = privkey.(*mlkem.DecapsulationKey1024).EncapsulationKey().Bytes()
	}

	n, err := clientConn.Write(pubkeyb)
	if err != nil || n != ENCAP_KEY_SIZES[args.Bits] {
		return res.re(&Err{
			reason: "failed to send public key to the client",
			err:    err,
		})
	}

	// Step 3: Receive the ciphertext.
	buf, n, err := readonce(clientConn, CIPHERTEXT_SIZES[args.Bits], &readopts{
		timeout: args.Timeout,
		full:    true,
	})

	if err != nil || n != CIPHERTEXT_SIZES[args.Bits] {
		return res.re(&Err{
			reason: "failed to get ciphertext from the client",
			err:    err,
		})
	}

	// Step 4: Decapsulate the chipertext.
	if args.Bits == 768 {
		res.Key, err = privkey.(*mlkem.DecapsulationKey768).Decapsulate(buf)
	} else {
		res.Key, err = privkey.(*mlkem.DecapsulationKey1024).Decapsulate(buf)
	}

	if err != nil {
		return res.re(&Err{
			reason: "failed to decapsulate the ciphertext",
			err:    err,
		})
	}

	// Step 5: Send ACK.
	msg := []byte{0, 8, 0, 8}
	msg = append(msg, randbytes(6)...)
	msg, err = res.Encrypt(msg)

	if err != nil {
		return res.re(&Err{
			reason: "failed to encrypt the ack message",
			err:    err,
		})
	}

	n, err = clientConn.Write(msg)

	if err != nil || n != len(msg) {
		return res.re(&Err{
			reason: "failed to send the ack message",
			err:    err,
		})
	}

	// Step 6: Receive the ID and meta data.
	buf, n, err = readonce(clientConn, int(args.MaxIdMetaSize), &readopts{
		timeout: args.Timeout,
	})

	if err != nil {
		return res.re(&Err{
			reason: "failed to receive the ID and meta data",
			err:    err,
		})
	}

	idme, err := res.Decrypt(buf[:n])

	if err != nil {
		return res.re(&Err{
			reason: "failed to decrypt the ID and meta data",
			err:    err,
		})
	}

	if len(idme) < int(args.MinIdMetaSize) {
		return res.re(&Err{
			reason: "ID and meta data message is too short",
			err:    fmt.Errorf("received: %d, must be at least %d bytes", len(idme), args.MinIdMetaSize),
		})
	}

	if len(idme) > int(args.MaxIdMetaSize) {
		return res.re(&Err{
			reason: "ID and meta data message is too long",
			err:    fmt.Errorf("received: %d, must be at most %d bytes", len(idme), args.MaxIdMetaSize),
		})
	}

	id, meta, err := decodeIdMeta(idme)

	if err != nil {
		return res.re(&Err{
			reason: "failed to decode the ID and meta data",
			err:    err,
		})
	}

	res.ID = id
	res.Meta = meta

	// Step 7: Send the challenge.
	challenge := randbytes(CHALLENGE_SIZE)
	encryptedChlng, err := res.Encrypt(challenge)

	if err != nil {
		return res.re(&Err{
			reason: "failed to encrypt the challenge message",
			err:    errors.New("failed to encrypt the challenge message"),
		})
	}

	n, err = clientConn.Write(encryptedChlng)

	if err != nil || n != len(encryptedChlng) {
		return res.re(&Err{
			reason: "failed to write the challenge message",
			err:    err,
		})
	}

	// Step 8: Get the encrypted signed message size.
	buf, n, err = readonce(clientConn, 2, &readopts{
		timeout: args.Timeout,
		full:    true,
	})

	if err != nil || n != 2 {
		return res.re(&Err{
			reason: "failed to get the encrypted message size",
			err:    err,
		})
	}

	encsize := binary.BigEndian.Uint16(buf)
	decsize := encsize - 28

	if decsize < args.MinSigSize || decsize > args.MaxSigSize {
		return res.re(&Err{
			reason: "received invalid signature size",
			err:    fmt.Errorf("received: %d, min: %d, max: %d", decsize, args.MinSigSize, args.MaxSigSize),
		})
	}

	// Step 8: Get the signed message.
	buf, n, err = readonce(clientConn, int(encsize), &readopts{
		timeout: args.Timeout,
		full:    true,
	})

	if err != nil {
		return res.re(&Err{
			reason: "failed to get the signature",
			err:    err,
		})
	}

	dsig, err := res.Decrypt(buf[:n])

	if err != nil {
		return res.re(&Err{
			reason: "failed to decrypt the signature",
			err:    err,
		})
	}

	// Step 9: Verify the signature
	if ok, err := args.VerifySig(res, challenge, dsig); !ok {
		if err == nil {
			err = errors.New("signatures didn't match")
		}

		return res.re(&Err{
			reason: "failed to verify the signature",
			err:    err,
		})
	}

	// Step 10: Send the confirmation
	cnfm, err := res.Encrypt(challenge)

	if err != nil {
		return res.re(&Err{
			reason: "failed to encrypt the confirmation message",
			err:    err,
		})
	}

	n, err = clientConn.Write(cnfm)

	if err != nil || n != len(cnfm) {
		return res.re(&Err{
			reason: "failed to send the confirmation message",
			err:    err,
		})
	}

	if args.DelayOnAuth > 0 {
		time.Sleep(args.DelayOnAuth)
	}

	res.time = time.Now()

	return res
}
