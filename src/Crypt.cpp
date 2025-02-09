#include "Crypt.h"
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

Crypt::Crypt() 
{
    if (BCryptOpenAlgorithmProvider(&m_hEcdhAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0) != 0)
        throw std::runtime_error("Failed to open ECDH algorithm provider");
        
    if (BCryptGenerateKeyPair(m_hEcdhAlg, &m_hEcdhKey, 255, 0) != 0)
        throw std::runtime_error("Failed to generate ECDH key pair");
        
    if (BCryptFinalizeKeyPair(m_hEcdhKey, 0) != 0)
        throw std::runtime_error("Failed to finalize key pair");
}

Crypt::~Crypt() 
{
    if (m_hEcdhKey) BCryptDestroyKey(m_hEcdhKey);
    if (m_hEcdhAlg) BCryptCloseAlgorithmProvider(m_hEcdhAlg, 0);
    if (m_hAesKey) BCryptDestroyKey(m_hAesKey);
    if (m_hAesAlg) BCryptCloseAlgorithmProvider(m_hAesAlg, 0);
}

std::vector<BYTE> Crypt::GetPublicKey() {
    DWORD keySize = 0;
    BCryptExportKey(m_hEcdhKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &keySize, 0);
    std::vector<BYTE> publicKey(keySize);
    if (BCryptExportKey(m_hEcdhKey, NULL, BCRYPT_ECCPUBLIC_BLOB, publicKey.data(), keySize, &keySize, 0) != 0)
        throw std::runtime_error("Failed to export public key");
    return publicKey;
}

void Crypt::DeriveSecret(const std::vector<BYTE>& peerPublicKey) 
{
    BCRYPT_KEY_HANDLE peerKey;
    if (BCryptImportKeyPair(m_hEcdhAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &peerKey, (PUCHAR)peerPublicKey.data(), peerPublicKey.size(), 0) != 0)
        throw std::runtime_error("Failed to import peer public key");
        
    DWORD secretSize = 0;
    BCryptSecretAgreement(m_hEcdhKey, peerKey, &m_sharedSecret, 0);
    BCryptDeriveKey(m_sharedSecret, BCRYPT_KDF_HKDF, NULL, m_derivedKey, sizeof(m_derivedKey), &secretSize, 0);
        
    BCryptDestroyKey(peerKey);
}

void Crypt::GenerateAesKey()
{
    if (BCryptOpenAlgorithmProvider(&m_hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        throw std::runtime_error("Failed to open AES algorithm provider");
    
    if (BCryptGenerateSymmetricKey(m_hAesAlg, &m_hAesKey, NULL, 0, m_derivedKey, sizeof(m_derivedKey), 0) != 0)
        throw std::runtime_error("Failed to generate AES key");
}

void Crypt::Encrypt(const std::vector<BYTE>& plaintext, std::vector<BYTE>& ciphertext, std::vector<BYTE>& tag) 
{
        // AES-GCM encryption to be implemented
        DWORD cipherTextSize = 0;
        BCryptEncrypt(m_hAesKey, (PUCHAR)plaintext.data(), plaintext.size(), NULL, NULL, 0, NULL, 0, &cipherTextSize, BCRYPT_BLOCK_PADDING);
        ciphertext.resize(cipherTextSize);
        
        if (BCryptEncrypt(m_hAesKey, (PUCHAR)plaintext.data(), plaintext.size(), NULL, NULL, 0, ciphertext.data(), cipherTextSize, &cipherTextSize, BCRYPT_BLOCK_PADDING) != 0)
            throw std::runtime_error("Failed to encrypt data");
        
}

void Crypt::Decrypt(const std::vector<BYTE>& ciphertext, std::vector<BYTE>& plaintext, std::vector<BYTE>& tag) 
{
    // AES-GCM decryption to be implemented
    DWORD plainTextSize = 0;
    BCryptDecrypt(m_hAesKey, (PUCHAR)ciphertext.data(), ciphertext.size(), NULL, NULL, 0, NULL, 0, &plainTextSize, BCRYPT_BLOCK_PADDING);
    plaintext.resize(plainTextSize);
    
    if (BCryptDecrypt(m_hAesKey, (PUCHAR)ciphertext.data(), ciphertext.size(), NULL, NULL, 0, plaintext.data(), plainTextSize, &plainTextSize, BCRYPT_BLOCK_PADDING) != 0)
        throw std::runtime_error("Failed to decrypt data");
    
}

