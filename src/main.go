package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"go.mozilla.org/pkcs7"
)

// https://pkg.go.dev/go.mozilla.org/pkcs7#section-sourcefiles
// https://github.com/mozilla-services/pkcs7/blob/33d05740a352/verify_test_dsa.go
func main() {

	log.Println("Start")

	certificatePath := os.Getenv("CERTIFICATE_PATH")
	if certificatePath == "" {
		log.Fatalln("CERTIFICATE_PATH environment variable must be set with proper value")
	}

	keyPath := os.Getenv("PRIVATE_KEY_PATH")
	if keyPath == "" {
		log.Fatalln("PRIVATE_KEY_PATH environment variable must be set with proper value")
	}

	x509cert, rsaPrivKey := LoadX509KeyPair(certificatePath, keyPath)
	// log.Println(x509cert)
	// log.Println(rsaPrivKey)

	inputPath := os.Getenv("INPUT_PATH")
	if inputPath == "" {
		log.Println("INPUT_PATH environment variable must be set with proper value. Using fallback './input.txt'")
		inputPath = "./input.txt"
	}
	content, err := loadContentToBeSigned(inputPath)
	if err != nil {
		log.Fatal("Não foi possível carregar o conteúdo a ser assinado")
	}
	// log.Println(content)

	signed, err := SignAndDetach(content, x509cert, rsaPrivKey)
	if err != nil {
		log.Println("Failed to sign content!")
	}
	// log.Println("Content Signed ", signed)

	err = saveSignatureFile(signed)
	if err != nil {
		log.Println(err)
	}

	log.Println("Finish")
}

func LoadX509KeyPair(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey) {

	cf, e := os.ReadFile(certFile)
	if e != nil {
		log.Fatal("failed to load certificate file:", e.Error())
	}

	kf, e := os.ReadFile(keyFile)
	if e != nil {
		log.Fatal("failed to load private key:", e.Error())
	}
	cpb, _ := pem.Decode(cf)
	// fmt.Println(string(cr))
	kpb, _ := pem.Decode(kf)
	// fmt.Println(string(kr))
	crt, e := x509.ParseCertificate(cpb.Bytes)

	if e != nil {
		log.Fatalln("failed to parse x509:", e.Error())
	}
	key, e := x509.ParsePKCS8PrivateKey(kpb.Bytes)
	if e != nil {
		log.Fatalln("failed to parse key:", e.Error())
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil
	} else {
		return crt, rsaKey
	}
}

// Sign using Brazil standards as seen in https://pbad.labsec.ufsc.br/verifier-hom/
func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {

	toBeSigned, err := pkcs7.NewSignedData(content)

	// SHA256 is required to compliance in Brasil
	toBeSigned.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	if err != nil {
		log.Printf("Cannot initialize signed data: %s", err)
		return nil, err
	}
	signerInfo := pkcs7.SignerInfoConfig{}
	if err = toBeSigned.AddSigner(cert, privkey, signerInfo); err != nil {
		log.Printf("Cannot add signer: %s", err)
		return nil, err
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		log.Printf("Cannot finish signing data: %s", err)
		return
	}

	// Show base64 PKCS7
	// pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

	// Parse Verify the signature
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Printf("Cannot parse our signed data: %s", err)
		return nil, err
	}

	// since the signature was detached, reattach the content here to validate
	p7.Content = content

	if !bytes.Equal(content, p7.Content) {
		log.Printf("our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		return nil, err
	}
	if err = p7.Verify(); err != nil {
		log.Printf("cannot verify our signed data: %s", err)
		return nil, err
	}

	return signed, nil
}

// load from storage
func loadContentToBeSigned(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// save in storage
func saveSignatureFile(content []byte) error {
	outputPath := os.Getenv("OUTPUT_PATH")
	if outputPath == "" {
		log.Println("OUTPUT_PATH environment variable must be set with proper value. Using fallback './output.p7s'")
		outputPath = "./output.p7s"
	}

	err := os.WriteFile(outputPath, content, 0644)
	if err != nil {
		log.Println("failed to save file ", err)
		return err
	}
	log.Println("Signature saved at", outputPath)

	return nil
}
