package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"encoding/pem"
	"errors"
	"os"

	"github.com/LarryBattle/nonce-golang"
	"github.com/gansidui/gotcp/examples/echo"
)

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

func LoadPrivateKey(private_key_file string) (*rsa.PrivateKey, error) {
	privIn := make([]byte, 5000)

	f, err := os.Open(private_key_file)
	checkError(err)
	_, err = f.Read(privIn)
	checkError(err)

	// Import the keys from pem string
	priv_parsed, err := ParseRsaPrivateKeyFromPemStr(string(privIn))

	return priv_parsed, err
}

func LoadPublicKey(public_key_file string) (*rsa.PublicKey, error) {
	pubIn := make([]byte, 5000)

	f, err := os.Open(public_key_file)
	checkError(err)
	_, err = f.Read(pubIn)
	checkError(err)

	// Import the keys from pem string
	pub_parsed, err := ParseRsaPublicKeyFromPemStr(string(pubIn))

	return pub_parsed, err
}

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:8989")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)

	echoProtocol := &echo.EchoProtocol{}

	// Load private key dari client
	clientPrivateKey, err := LoadPrivateKey("client_private.key")
	checkError(err)

	// Load public key dari server
	serverPublicKey, err := LoadPublicKey("server_public.key")
	_, err = LoadPublicKey("server_public.key")
	checkError(err)

	// Untuk menyimpan data bytes dari server
	packetBytes := []byte("asd")

	/*

		Step 1:	Kirim ID dan nonce 1 ke server (B), enkripsi menggunakan public key dari server (B)

		Step 2:	Menerima nonce 1 dan nonce 2 dari server (B) yang dienkripsi menggunakan public key
				dari client (A).

				Kirim nonce 2, enkripsi menggunakan public key dari server (B)

		Step 3:	Kirim secret key yang dienkripsi menggunakan private key client (A), kemudian
				dienkripsi lagi menggunakan public key dari server (B)

	*/

	var nonce1_original = []byte("")
	var hasError = false

	for i := 0; i < 3; i++ {
		switch i {

		// Step 1
		case 0:
			fmt.Println("===== Step 1 =====")

			fmt.Println("Mengirim ID dari client (A) dan nonce 1 yang dienkripsi")
			fmt.Println("menggunakan public key dari server (B)")

			// Buat ID A, panjang ID 32 byte
			id := []byte(nonce.NewToken())

			// Buat nonce 1, panjang nonce adalah 32 byte
			nonce1 := []byte(nonce.NewToken())

			// Simpan nonce 1 yang original untuk dicek di step berikutnya
			nonce1_original = nonce1

			// Gabungkan ID A dan nonce 1
			data := append(id, nonce1...)

			// Enkripsi menggunakan public key dari server (B)
			encryptedData, err := rsa.EncryptOAEP(
				sha256.New(),
				rand.Reader,
				serverPublicKey,
				data,
				[]byte(""),
			)
			checkError(err)

			// Kirim data ke server
			conn.Write(echo.NewEchoPacket(encryptedData, false).Serialize())

			fmt.Println()

		// Step 2
		case 1:
			fmt.Println("===== Step 2 =====")

			fmt.Println("Mendekripsi data yang diterima dari server (B)")
			fmt.Println("menggunakan private key dari client (A)")

			decryptedBytes, err := clientPrivateKey.Decrypt(
				nil,
				packetBytes,
				&rsa.OAEPOptions{Hash: crypto.SHA256},
			)

			// Ambil nonce 1 dan nonce 2
			nonce1 := decryptedBytes[:32]
			nonce2 := decryptedBytes[32:]

			fmt.Println("Nonce 1 = " + string(nonce1))
			fmt.Println("Nonce 2 = " + string(nonce2))

			// Bandingkan nonce 1 yang diterima dengan nonce 1 original
			if string(nonce1) != string(nonce1_original) {
				fmt.Println("Nonce yang diterima salah!")

				hasError = true
				break
			}

			fmt.Println("Mengirim nonce 2 yang diterima dari server (B) yang dienkripsi")
			fmt.Println("menggunakan public key dari server (B)")

			// Enkripsi nonce 2 menggunakan public key dari server (B)
			encryptedData, err := rsa.EncryptOAEP(
				sha256.New(),
				rand.Reader,
				serverPublicKey,
				nonce2,
				[]byte(""),
			)
			checkError(err)

			conn.Write(echo.NewEchoPacket(encryptedData, false).Serialize())

			fmt.Println()

		// Step 3
		case 2:
			fmt.Println("===== Step 3 =====")

			fmt.Println("Mengirim secret key yang disign menggunakan private key")
			fmt.Println("dari client (A), kemudian dienkripsi lagi menggunakan")
			fmt.Println("public key dari server (B)")

			secretKey := []byte("secretkeysecretkeysecretkeysecretkey")
			secretKey = secretKey[:32] // Ambil 32 bytes pertama

			// Buat hash dan signature dari secret key
			secretKeyHash := sha256.New()
			_, err = secretKeyHash.Write(secretKey)
			checkError(err)
			secretKeyHashSum := secretKeyHash.Sum(nil)

			signature, err := rsa.SignPSS(rand.Reader, clientPrivateKey, crypto.SHA256, secretKeyHashSum, nil)
			checkError(err)

			// Gabungkan secret key dengan signature dari secret key
			_ = signature
			data := append(secretKey, signature...)
			encryptedData := []byte("")

			// Jika ukuran data lebih besar dari ukuran key,
			// bagi menjadi beberapa blok
			// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt
			blockSize := serverPublicKey.Size() - 2*sha256.New().Size() - 2

			if len(data) > blockSize {
				blockCount := (len(data) + blockSize - 1) / blockSize

				// Enkripsi data secret key dan signature dari secret key
				// menggunakan public key dari server (B)
				for i := 0; i < blockCount; i++ {
					encryptedBlock := []byte("")

					if i < blockCount-1 {
						encryptedBlock, err = rsa.EncryptOAEP(
							sha256.New(),
							rand.Reader,
							serverPublicKey,
							data[blockSize*i:blockSize*(i+1)],
							[]byte(""),
						)
						checkError(err)
					} else {
						encryptedBlock, err = rsa.EncryptOAEP(
							sha256.New(),
							rand.Reader,
							serverPublicKey,
							data[blockSize*i:],
							[]byte(""),
						)
						checkError(err)
					}

					encryptedData = append(encryptedData, encryptedBlock...)
				}
			} else {
				encryptedData, err = rsa.EncryptOAEP(
					sha256.New(),
					rand.Reader,
					serverPublicKey,
					data,
					[]byte(""),
				)
				checkError(err)
			}

			conn.Write(echo.NewEchoPacket(encryptedData, false).Serialize())

			fmt.Println()

		default:
			break
		}

		if hasError {
			break
		}

		// Baca dan proses reply dari server
		p, err := echoProtocol.ReadPacket(conn)
		if err == nil {
			echoPacket := p.(*echo.EchoPacket)

			// Simpan data yang diterima dari server
			packetBytes = echoPacket.GetBody()

			packetLen := echoPacket.GetLength()
			packetBody := string(packetBytes)

			fmt.Printf("Server reply:[%v] [%v]\n\n", packetLen, packetBody)

			if packetBody == "failed" {
				break
			}
		}

		time.Sleep(2 * time.Second)
	}

	conn.Close()
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
