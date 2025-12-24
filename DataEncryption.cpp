#include "DataEncryption.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <stdexcept>
#include <iostream>

const std::string DataEncryption::CIPHER_ALGORITHM = "aes-256-cbc";
const std::string DataEncryption::DIGEST_ALGORITHM = "sha256";

// Вспомогательный метод для создания умного указателя
DataEncryption::CipherContextPtr DataEncryption::createCipherContextRAII() {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    return CipherContextPtr(ctx);
}

std::string DataEncryption::encrypt(const std::string &plaintext, const std::string &password, const std::string &internal_key) {
    if (plaintext.empty()) throw std::invalid_argument("Plaintext cannot be empty");
    if (password.empty()) throw std::invalid_argument("Password cannot be empty");

    auto salt = generateSalt();
    auto iv = generateIV();
    auto key = deriveKey(password, salt, internal_key);

    // Использование умного указателя - авто-удаление при выходе из scope
    CipherContextPtr ctx = createCipherContextRAII();

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char *>(plaintext.data()),
                          plaintext.size()) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    // Контекст удалится автоматически здесь

    std::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext_len);
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    return encodeBase64(result);
}

std::string DataEncryption::decrypt(const std::string& ciphertext, const std::string& password, const std::string& internal_key) {
    if (ciphertext.empty()) throw std::invalid_argument("Ciphertext cannot be empty");
    if (password.empty()) throw std::invalid_argument("Password cannot be empty");

    std::vector<unsigned char> data = decodeBase64(ciphertext);
    if (data.size() < SALT_LENGTH + IV_LENGTH) throw std::runtime_error("Invalid ciphertext format");

    std::vector<unsigned char> salt(data.begin(), data.begin() + SALT_LENGTH);
    std::vector<unsigned char> iv(data.begin() + SALT_LENGTH, data.begin() + SALT_LENGTH + IV_LENGTH);
    std::vector<unsigned char> encrypted_data(data.begin() + SALT_LENGTH + IV_LENGTH, data.end());

    auto key = deriveKey(password, salt, internal_key);

    // Использование умного указателя
    CipherContextPtr ctx = createCipherContextRAII();

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> plaintext(encrypted_data.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, encrypted_data.data(), encrypted_data.size()) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw std::runtime_error("Failed to finalize decryption - possible wrong password");
    }
    plaintext_len += len;

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

std::vector<unsigned char> DataEncryption::deriveKey(const std::string& password, const std::vector<unsigned char>& salt, const std::string& internal_key) {
    std::vector<unsigned char> key(KEY_LENGTH);
    std::string combined_password = password + internal_key;

    if (PKCS5_PBKDF2_HMAC(combined_password.c_str(), combined_password.length(),
                          salt.data(), salt.size(), ITERATIONS, EVP_sha256(),
                          KEY_LENGTH, key.data()) != 1) {
        throw std::runtime_error("Failed to derive key from password");
    }
    return key;
}

std::vector<unsigned char> DataEncryption::generateSalt() {
    std::vector<unsigned char> salt(SALT_LENGTH);
    if (RAND_bytes(salt.data(), SALT_LENGTH) != 1) throw std::runtime_error("Failed to generate salt");
    return salt;
}

std::vector<unsigned char> DataEncryption::generateIV() {
    std::vector<unsigned char> iv(IV_LENGTH);
    if (RAND_bytes(iv.data(), IV_LENGTH) != 1) throw std::runtime_error("Failed to generate IV");
    return iv;
}

std::string DataEncryption::encodeBase64(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<unsigned char> DataEncryption::decodeBase64(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(data.data(), data.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    std::vector<unsigned char> result(data.length());
    int length = BIO_read(bio, result.data(), data.length());
    BIO_free_all(bio);
    if (length > 0) result.resize(length);
    else throw std::runtime_error("Failed to decode Base64 data");
    return result;
}

bool DataEncryption::verifyIntegrity(const std::string& ciphertext, const std::string& password, const std::string& internal_key) {
    try {
        decrypt(ciphertext, password, internal_key);
        return true;
    } catch (...) {
        return false;
    }
}

bool DataEncryption::initializeCrypto() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return true;
}

void DataEncryption::cleanupCrypto() {
    EVP_cleanup();
    ERR_free_strings();
}