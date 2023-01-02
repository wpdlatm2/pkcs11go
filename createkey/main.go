package main

import (
	"bytes"
	"encoding/binary"
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

	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // we don't need to extract this..
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, make([]byte, 32)), // KeyLength 256bit
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "AESKey"),         // Name of Key
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	aesKey, err := p.CreateObject(session, aesKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
	}

	log.Printf("Created AES Key: %v", aesKey)


}
