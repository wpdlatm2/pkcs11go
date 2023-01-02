package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

const (
	pin = "user"
)

var ()

func main() {

	// Init PKCS for Linux 
	//	p := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	
	// Init PKCS for Windows
	// p := pkcs11.New("D:\\SoftHSM2\\lib\\softhsm2-x64.dll")
	
	// Init PKCS for MACOS
	p := pkcs11.New("/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so")
	
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("CryptokiVersion.Major %v", info.CryptokiVersion.Major)

	fmt.Println()

	//   1.  Create AES key, test encryption and decryption

	// first lookup the key
	buf := new(bytes.Buffer)
	var num uint16 = 1
	err = binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	id := buf.Bytes()

	/*
		aesKeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, false),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we don't need to extract this..
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), // KeyLength
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKey"),         // Name of Key
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}

			aesKey, err := p.CreateObject(session, aesKeyTemplate)
			if err != nil {
				panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
			}

			randGen, err := p.GenerateRandom(session, 32)
			if err != nil {
				panic(fmt.Sprintf("GenerateRandom() failed %s\n", err))
			}

			log.Printf("Created AES Key: %v", aesKey)
			log.Printf("Created Random: %v", randGen)

	*/

	ktemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKey"),
	}
	if err := p.FindObjectsInit(session, ktemplate); err != nil {
		panic(err)
	}
	kobjs, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(err)
	}

	aesKey := kobjs[0]

	iv := make([]byte, 16)
	_, err = rand.Read(iv)

	if err != nil {
		panic(err)
	}

	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, kobjs[0])
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	ct, err := p.Encrypt(session, []byte("922fbd10acb293d8e9246c1d04dd9ac553c586983340f911f36d46d142c17541aaa373d84cb40e87e12cf24280c765f9e9da9fd0a18f0854537005d841a8e8e572b8e10ea644a62a7114e59b35fd20215edd48e2aa8e9625932361027e48304a561f839d367ca26498e2e16a55ea88bceedf5953361159e95201a3d8c598f25a277a9563cf346795426039f4db6213a9a3388c690fa26adcb5da268b7a124204e95ab92d7b241f6168662f5b7d35edba3d37bea0c91b22c5d4e1aeb811e99916cb2f658defc8a2b1f52637b1f883a9c202b15192428affce446655744f121591ec8b4c8e0550c205925ce51fdffd91708d785fcb7e4a2a0782757da31f39edf5b43d6e09d0052ca3e1c7fe0029e7e4b7669e6257d0d31ede8827a2c174bedf84b336396c100046287f54c070f87d82b973adc5877c3b572467e5388c2a2b92de4edaf623b9bf506f9764c747c942c7624fa758efcb2b2e1fe0f7d28e06232b7ce8f915ff6e2357c02c8ef3c79b47d88f9ca139d3ad7918db069873e4ee05faae144626397b443447fde209f170ce2761fc13210131e7c0d1fd364832fc8953d7ae8701b739bdd99aaea6d0a1cac7e4e5d52421d87e99ad1f32a3018fcf97732c27c1f2d2edbcf8cbb20a177728b25d02341bf038a390ba5a7552bdd8a7803438f196d90ee1ad8783505a8680c3a3ed90cfdcd7a15fda92a40abdbd10eecd840b"))
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	// append the IV to the ciphertext
	cdWithIV := append(iv, ct...)

	log.Printf("Encrypted Ciphertext to hex string %s", hex.EncodeToString(ct))
	log.Printf("Encrypted IV+Ciphertext %s", base64.RawStdEncoding.EncodeToString(cdWithIV))

	//	aesKey := kobjs[0]

	err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, cdWithIV[0:16])}, aesKey)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	pt, err := p.Decrypt(session, ct[:])
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	log.Printf("Decrypt %s", string(pt))

}
