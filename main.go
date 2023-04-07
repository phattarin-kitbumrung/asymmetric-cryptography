package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	generateKey()
	ciphertext := encrypt("My name is minizymint.")
	decrypt(ciphertext)
}

func generateKey() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile("private.pem", privateKeyPEM, 0644)
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile("public.pem", publicKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
}

func encrypt(plaintext string) string {
	publicKeyPEM, err := ioutil.ReadFile("public.pem")
	if err != nil {
		panic(err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// encrypting data
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), []byte(plaintext))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted: %x\n", ciphertext)

	return string(ciphertext)
}

func decrypt(ciphertext string) string {
	privateKeyPEM, err := ioutil.ReadFile("private.pem")
	if err != nil {
		panic(err)
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	// decrypting data
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, []byte(ciphertext))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted: %s\n", plaintext)

	return string(plaintext)
}
