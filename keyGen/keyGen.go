package sshKeyGen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	keygen "github.com/night-codes/go-keygen"
	"golang.org/x/crypto/ssh"
)

type (
	// SSHKeypair with values as keys and password as strings
	SSHKeypair struct {
		PrivateKey string
		PublicKey  string
		Password   string
	}
)

const (
	rsaPEMType = "RSA PRIVATE KEY"
)

// MarshalRSAKeyDER marshal rsa key
func MarshalRSAKeyDER(privateKey *rsa.PrivateKey) (derBytes []byte) {
	derBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	return
}

// MarshalRSAKeyPEM marshal rsa key
func MarshalRSAKeyPEM(privateKey *rsa.PrivateKey) (privateKeyPEM *pem.Block) {
	privateKeyPEM = new(pem.Block)
	*privateKeyPEM = pem.Block{
		Type:  rsaPEMType,
		Bytes: MarshalRSAKeyDER(privateKey),
	}
	return
}

// MarshalRSAKeyEncryptedPEM marshal rsa key
func MarshalRSAKeyEncryptedPEM(privateKey *rsa.PrivateKey, password string) (privateKeyPEM *pem.Block) {
	derBytes := MarshalRSAKeyDER(privateKey)
	privateKeyPEM, err := x509.EncryptPEMBlock(
		rand.Reader, rsaPEMType, derBytes, []byte(password), x509.PEMCipherAES256)
	l.Check(err, 1, "rsa key generation in GenerateRSAKeyEncryptedPEM")
	return
}

// GenerateRSAKey generate rsa key
func GenerateRSAKey(rsaBits int) (privateKey *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	l.Check(err, 1, "rsa key generation in GenerateRSAKeyPEM")
	return
}

// GenerateRSAKeyDER generate rsa key
func GenerateRSAKeyDER(rsaBits int) (derBytes []byte) {
	derBytes = x509.MarshalPKCS1PrivateKey(GenerateRSAKey(rsaBits))
	return
}

// GenerateRSAKeyPEM generate rsa key
func GenerateRSAKeyPEM(rsaBits int) (privateKeyPEM *pem.Block) {
	privateKeyPEM = new(pem.Block)
	*privateKeyPEM = pem.Block{
		Type:  rsaPEMType,
		Bytes: GenerateRSAKeyDER(rsaBits),
	}
	return
}

// GenerateRSAKeyEncryptedPEM generate rsa key
func GenerateRSAKeyEncryptedPEM(rsaBits int, password string) (privateKeyPEM *pem.Block) {
	derBytes := GenerateRSAKeyDER(rsaBits)
	privateKeyPEM, err := x509.EncryptPEMBlock(
		rand.Reader, rsaPEMType, derBytes, []byte(password), x509.PEMCipherAES256)
	l.Check(err, 1, "rsa key generation in GenerateRSAKeyEncryptedPEM")
	return
}

// GenerateSSHKey generate ssh key
func GenerateSSHKey(rsaBits int, rsaPasswordLength int) (sshKeypair SSHKeypair) {

	privateKey := GenerateRSAKey(rsaBits)

	var privateKeyPEM *pem.Block
	if rsaPasswordLength > 0 {
		sshKeypair.Password = keygen.NewPass(rsaPasswordLength)
		privateKeyPEM = MarshalRSAKeyEncryptedPEM(privateKey, sshKeypair.Password)
	} else {
		privateKeyPEM = MarshalRSAKeyPEM(privateKey)
	}

	sshPublicKey, err := ssh.NewPublicKey(privateKey)
	l.Check(err, 1, "generating ssh public key")

	sshKeypair.PrivateKey = string(pem.EncodeToMemory(privateKeyPEM))
	sshKeypair.PublicKey = string(ssh.MarshalAuthorizedKey(sshPublicKey))
	return
}
