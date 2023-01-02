package main

import (
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

	Randvalue, err := p.GenerateRandom(session, 32)
	if err != nil {
		panic(fmt.Sprintf("GenerateRandom() failed %s\n", err))
	}

	Randvalue_hex := hex.EncodeToString(Randvalue)
	log.Printf("slot info: %s", slots)
	log.Printf("info: %s", info)
	log.Printf("Created Random: %s", Randvalue_hex)
	//	log.Printf("Created Random: %v", Randvalue_hex)

}
