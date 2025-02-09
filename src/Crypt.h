#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <vector>
#include <mutex>

#pragma comment(lib, "bcrypt")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

class Crypt {
public:
	Crypt();
	~Crypt();
	std::vector<BYTE>GetPublicKey();
	void Encrypt(const std::vector<BYTE>& plaintext, std::vector<BYTE>& ciphertext, std::vector<BYTE>& tag);
	void Decrypt(const std::vector<BYTE>& ciphertext, std::vector<BYTE>& plaintext, std::vector<BYTE>& tag);

private:
	void DeriveSecret(const std::vector<BYTE>& peerPublicKey);
	void GenerateAesKey();
	
	BCRYPT_ALG_HANDLE m_hEcdhAlg = NULL;
	BCRYPT_KEY_HANDLE m_hEcdhKey = NULL;
	BCRYPT_ALG_HANDLE m_hAesAlg = NULL;
	BCRYPT_KEY_HANDLE m_hAesKey = NULL;
	BCRYPT_SECRET_HANDLE m_sharedSecret = NULL;
	BYTE m_derivedKey[32];

};
