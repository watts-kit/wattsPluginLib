package sshKeyGen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	keygen "github.com/night-codes/go-keygen"
	"golang.org/x/crypto/ssh"
)


// GenerateKey generate a rsa keypair with rsaBits length and a password of length rsaPasswordLength
// the key pair is directly usable as a ssh keypair
func GenerateKey(rsaBits int, rsaPasswordLength int) (privateKey string, publicKey string, password string, err error) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
	}
	if rsaPasswordLength > 0 {
		password = keygen.NewPass(rsaPasswordLength)
		pemBlock, err = x509.EncryptPEMBlock(
			rand.Reader, pemBlock.Type, pemBlock.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return
		}
	}

	sshPublicKey, err := ssh.NewPublicKey(&rsaPrivateKey.PublicKey)
	if err != nil {
		return
	}

	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	publicKeyAuthKey := ssh.MarshalAuthorizedKey(sshPublicKey)

	// removing a trailing newline here
	privateKey = string(privateKeyPEM[:len(privateKeyPEM)-1])
	publicKey = string(publicKeyAuthKey[:len(publicKeyAuthKey)-1])
	err = nil
	return
}
