# pkcs11go
softhsm2 + pkcs11

golang에서 pkcs11으로 HSM에 키생성, 암호화, 복호화, 안전한 랜덤값 생성을 각각의 기능 단위로 구현함
Key generation, encryption, decryption, and secure random value generation are implemented in each function unit in the HSM with pkcs11 in golang

사용을 위해서는 pkcs11을 지원하는 software HSM이나 물리HSM의 사전 구성이 필요함
Pre-configuration of software HSM or physical HSM that supports pkcs11 is required for use.

구현환경은 윈도우에 softHSM2를 설치하였지만, 리눅스용 softHSM으로도 가능
For the implementation environment, softHSM2 was installed on Windows, but softHSM for Linux is also available.
