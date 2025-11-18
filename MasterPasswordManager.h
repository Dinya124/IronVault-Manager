#ifndef IRONVAULT_MANAGER_MASTERPASSWORDMANAGER_H
#define IRONVAULT_MANAGER_MASTERPASSWORDMANAGER_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>


class MasterPasswordManager {
private:
    std::string password_hash;
    std::vector<unsigned char> salt;

    // Константы
    static const size_t SALT_LENGTH = 16;     // 128 бит для соли
    static const size_t HASH_LENGTH = 32;     // 256 бит для SHA-256
    static const int PBKDF2_ITERATIONS = 100000; // Количество итераций

public:
    // Конструкторы
    MasterPasswordManager();
    explicit MasterPasswordManager(const std::string& stored_hash, const std::vector<unsigned char>& salt);

    // Основные методы
    static std::string hashPassword(const std::string& password);
    static bool verifyPassword(const std::string& password, const std::string& stored_hash);
    bool setNewPassword(const std::string& old_password, const std::string& new_password);
    void forceSetNewPassword(const std::string& new_password);

};


#endif //IRONVAULT_MANAGER_MASTERPASSWORDMANAGER_H
