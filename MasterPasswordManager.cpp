#include "MasterPasswordManager.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <map>

// Конструктор по умолчанию
MasterPasswordManager::MasterPasswordManager()
        : password_hash("") {
    salt = generateSalt();
}

// Конструктор с сохраненным хэшем и солью
MasterPasswordManager::MasterPasswordManager(const std::string &stored_hash, const std::vector<unsigned char> &salt)
        : password_hash(stored_hash), salt(salt) {

    if (salt.size() != SALT_LENGTH) {
        throw std::invalid_argument("Invalid salt length");
    }
}


// Хэширование пароля
std::string MasterPasswordManager::hashPassword(const std::string &password) {
    if (password.empty()) {
        throw std::invalid_argument("Password cannot be empty");
    }

    std::vector<unsigned char> new_salt = generateSalt();
    return hashWithSalt(password, new_salt);
}

// Проверка пароля
bool MasterPasswordManager::verifyPassword(const std::string &password, const std::string &stored_hash) {
    if (password.empty() || stored_hash.empty()) {
        return false;
    }

    try {
        // Парсим сохраненный хэш (формат: salt:hash)
        size_t separator_pos = stored_hash.find(':');
        if (separator_pos == std::string::npos) {
            return false;
        }

        std::string salt_str = stored_hash.substr(0, separator_pos);
        std::string expected_hash = stored_hash.substr(separator_pos + 1);

        std::vector<unsigned char> salt_vec = stringToVector(salt_str);
        std::string computed_hash = hashWithSalt(password, salt_vec);

        // Сравнение с постоянным временем для защиты от timing-атак
        return constantTimeCompare(computed_hash, expected_hash);

    } catch (const std::exception &e) {
        return false;
    }
}