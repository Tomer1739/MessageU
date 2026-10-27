#include "AESWrapper.h"

#include <cryptopp880/modes.h>
#include <cryptopp880/aes.h>
#include <cryptopp880/filters.h>

#include <stdexcept>
#include <cstring>
#include <immintrin.h>	// _rdrand32_step


unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
	{
		unsigned int random = 0;
		if (!_rdrand32_step(&random))
			throw std::runtime_error("failed to generate random key");
		// copy only what is left, so we never write past the buffer
		memcpy(&buffer[i], &random, (length - i < sizeof(unsigned int)) ? length - i : sizeof(unsigned int));
	}
	return buffer;
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 16 bytes");
	memcpy(_key, key, DEFAULT_KEYLENGTH);
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const
{
	return _key;
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}