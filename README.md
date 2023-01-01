# pkcs11go
softhsm2 + pkcs11

golang에서 pkcs11으로 HSM에 키생성, 암호화, 복호화, 안전한 랜덤값 생성을 각각의 기능 단위로 구현함
Key generation, encryption, decryption, and secure random value generation are implemented in each function unit in the HSM with pkcs11 in golang

사용을 위해서는 pkcs11을 지원하는 software HSM이나 물리HSM의 사전 구성이 필요함
Pre-configuration of software HSM or physical HSM that supports pkcs11 is required for use.

구현환경은 윈도우에 softHSM2를 설치하였지만, 리눅스용 softHSM으로도 가능
For the implementation environment, softHSM2 was installed on Windows, but softHSM for Linux is also available.

-------------------------------------------
Create Key
-------------------------------------------
createkey>main.exe
CryptokiVersion.Major 2
2023/01/01 13:40:47 Created AES Key: 2


-------------------------------------------
Encrypt / Decrypt using keys stored in HSM
-------------------------------------------
encrypt_decrypt>main.exe
CryptokiVersion.Major 2
2023/01/01 13:44:06 Encrypted Ciphertext to hex string 0b8bc6da2626ecb54a1a9a6f127dc3c3d4f9a0cf831316f89fd1b9bfb384176df84ae9c7902ca89e9314e50c563f5689cc72239442277c3cea5937a8eda783d5cef38d95af81c7a43cd74168654817d5
2023/01/01 13:44:06 Encrypted IV+Ciphertext 4/gjdPuNl4UJ36ypGyvbcAuLxtomJuy1ShqabxJ9w8PU+aDPgxMW+J/Rub+zhBdt+Erpx5AsqJ6TFOUMVj9WicxyI5RCJ3w86lk3qO2ng9XO842Vr4HHpDzXQWhlSBfV
2023/01/01 13:44:06 Decrypt 707b8035a2206b4dc5f7bdbbc80d818054ae0587f5d85c2de518ccbeeed508e5


-------------------------------------------
Secure random number generation using HSM
-------------------------------------------
main.exe
CryptokiVersion.Major 2
2023/01/01 13:46:03 slot info: [%!s(uint=1113379265) %!s(uint=1)]
2023/01/01 13:46:03 info: {{%!s(uint8=2) %!s(uint8=40)} SoftHSM %!s(uint=0) Implementation of PKCS11 {%!s(uint8=2) %!s(uint8=5)}}
2023/01/01 13:46:03 Created Random: 41da4c49c37290d3071011e46dd51b395dd3dfc006be7f5612833863dc3e60e6



