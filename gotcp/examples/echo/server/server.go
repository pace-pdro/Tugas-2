package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/LarryBattle/nonce-golang"
	"github.com/gansidui/gotcp"
	"github.com/gansidui/gotcp/examples/echo"
)

type Callback struct{}

/*
REPLY_STEP untuk menentukan reply yang dikirim ke client

SESSION_KEY adalah session key dari client yang akan digunakan
untuk mendekripsi data yang dikirim oleh client
*/

var REPLY_STEP = 0
var NONCE2_ORIGINAL = []byte("")

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

func (this *Callback) OnConnect(c *gotcp.Conn) bool {
	addr := c.GetRawConn().RemoteAddr()
	c.PutExtraData(addr)
	fmt.Println("OnConnect:", addr)
	return true
}

func (this *Callback) OnMessage(c *gotcp.Conn, p gotcp.Packet) bool {
	echoPacket := p.(*echo.EchoPacket)

	packetLen := echoPacket.GetLength()
	packetBody := echoPacket.GetBody()

	var reply = []byte("")

	switch REPLY_STEP {
	// Step 1
	case 0:
		// Load private key dari server
		fmt.Println("===== Step 1 =====")
		fmt.Println("Mendekripsi data dari A menggunakan private key server (B)")
		serverPrivateKey, err := LoadPrivateKey("server_private.key")
		checkError(err)

		// Dekripsi data ID dan nonce 1 dari client (A) menggunakan private key dari server (B)
		decrypted, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			serverPrivateKey,
			packetBody,
			[]byte(""),
		)

		// Ambil ID dan nonce 1
		id := decrypted[0:32]
		nonce1 := decrypted[32:]

		fmt.Println("ID A   = " + string(id))
		fmt.Println("Nonce1 = " + string(nonce1))

		// Load public key dari client (A)
		clientPublicKey, err := LoadPublicKey("client_public.key")
		checkError(err)

		// Buat nonce 2 dan enkripsi menggunakan public key dari client (A)
		nonce2 := []byte(nonce.NewToken())

		// Simpan nonce 2 untuk dicek di step berikutnya
		NONCE2_ORIGINAL = nonce2

		fmt.Println("Nonce2 = " + string(nonce2))

		data := append(nonce1, nonce2...)

		encryptedData, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			clientPublicKey,
			data,
			[]byte(""),
		)
		checkError(err)

		if err == nil {
			reply = encryptedData

			fmt.Println("ID dan nonce 1 diterima")
			fmt.Println("Mengirim nonce 1 dan nonce 2 ke client (A)")

			// Lanjut ke step 2
			REPLY_STEP = 1
		} else {
			reply = []byte("failed")

			// Balik ke step 1
			REPLY_STEP = 0
		}

		fmt.Println()

	// Step 2
	case 1:
		fmt.Println("===== Step 2 =====")

		// Load private key dari server
		fmt.Println("Mendekripsi data dari A menggunakan private key server (B)")
		serverPrivateKey, err := LoadPrivateKey("server_private.key")
		checkError(err)

		// Dekripsi data nonce 2 dari client (A) menggunakan private key dari server (B)
		nonce2, err := rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			serverPrivateKey,
			packetBody,
			[]byte(""),
		)
		checkError(err)

		// Pastikan nonce 2 yang dikirim sama dengan nonce 2 yang diterima
		if string(nonce2) != string(NONCE2_ORIGINAL) {
			fmt.Println("Nonce yang diterima dari client (A) berbeda dengan")
			fmt.Println("nonce yang dikirim sebelumnya oleh server (B)")

			reply = []byte("failed")

			// Balik ke step 1
			REPLY_STEP = 0
		} else {
			reply = []byte("ok")

			fmt.Println("Nonce yang diterima benar")
			fmt.Println(string(nonce2) + " = " + string(NONCE2_ORIGINAL))

			// Lanjut ke step 3
			REPLY_STEP = 2
		}

		fmt.Println()

	case 2:
		fmt.Println("===== Step 3 =====")

		// Load private key dari server (B)
		fmt.Println("Mendekripsi data dari client (A) menggunakan private key server (B)")
		serverPrivateKey, err := LoadPrivateKey("server_private.key")
		checkError(err)

		// Dekripsi blok - blok data dari client (A)
		decryptedData := []byte("")

		blockSize := serverPrivateKey.Size()

		if len(packetBody) > blockSize {
			blockCount := (len(packetBody) + blockSize - 1) / blockSize

			for i := 0; i < blockCount; i++ {
				decryptedBlock := []byte("")

				if i < blockCount-1 {
					decryptedBlock, err = rsa.DecryptOAEP(
						sha256.New(),
						rand.Reader,
						serverPrivateKey,
						packetBody[blockSize*i:blockSize*(i+1)],
						[]byte(""),
					)
				} else {
					decryptedBlock, err = rsa.DecryptOAEP(
						sha256.New(),
						rand.Reader,
						serverPrivateKey,
						packetBody[blockSize*i:],
						[]byte(""),
					)
				}

				checkError(err)

				decryptedData = append(decryptedData, decryptedBlock...)
			}
		} else {
			decryptedData, err = rsa.DecryptOAEP(
				sha256.New(),
				rand.Reader,
				serverPrivateKey,
				packetBody,
				[]byte(""),
			)
			checkError(err)
		}

		// Load public key dari client (A)
		fmt.Println("Memverifikasi data dari client (A) menggunakan public key dari client (A)")
		clientPublicKey, err := LoadPublicKey("client_public.key")
		checkError(err)

		// Ambil secret key dan signature dari secret key
		secretKey := decryptedData[:32]
		signature := decryptedData[32:]

		// Buat signature dari secret key yang diterima
		secretKeyHash := sha256.New()
		_, err = secretKeyHash.Write(secretKey)
		checkError(err)
		secretKeyHashSum := secretKeyHash.Sum(nil)

		err = rsa.VerifyPSS(clientPublicKey, crypto.SHA256, secretKeyHashSum, signature, nil)

		if err == nil {
			fmt.Println("Verifikasi signature berhasil")
			fmt.Println("Secret key = " + string(secretKey))

			reply = []byte("ok")
		} else {
			fmt.Println("Verifikasi signature gagal")
			fmt.Println(err)

			reply = []byte("failed")
		}

		// Balik ke step 1
		REPLY_STEP = 0

		fmt.Println()

	default:
		// Balik ke step 1
		REPLY_STEP = 0
	}

	fmt.Printf("OnMessage:[%v] [%v]\n\n", packetLen, string(packetBody))
	c.AsyncWritePacket(echo.NewEchoPacket(reply, false), time.Second)

	return true
}

func (this *Callback) OnClose(c *gotcp.Conn) {
	fmt.Println("OnClose:", c.GetExtraData())
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// creates a tcp listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":8989")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	// creates a server
	config := &gotcp.Config{
		PacketSendChanLimit:    2048,
		PacketReceiveChanLimit: 2048,
	}
	srv := gotcp.NewServer(config, &Callback{}, &echo.EchoProtocol{})

	// starts service
	go srv.Start(listener, time.Second)
	fmt.Println("listening:", listener.Addr())

	// catchs system signal
	chSig := make(chan os.Signal)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Signal: ", <-chSig)

	// stops service
	srv.Stop()
}

func checkError(err error) {
	REPLY_STEP = 0

	if err != nil {
		log.Fatal(err)
	}
}
