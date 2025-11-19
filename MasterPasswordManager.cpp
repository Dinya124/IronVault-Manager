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
#include <cmath>

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

// Установка нового пароля (с проверкой старого)
bool MasterPasswordManager::setNewPassword(const std::string &old_password, const std::string &new_password) {
    if (!isPasswordSet()) {
        // Пароль еще не установлен
        forceSetNewPassword(new_password);
        return true;
    }

    // Проверяем старый пароль
    if (!verifyPassword(old_password, password_hash)) {
        return false;
    }

    // Устанавливаем новый пароль
    forceSetNewPassword(new_password);
    return true;
}

// Принудительная установка нового пароля
void MasterPasswordManager::forceSetNewPassword(const std::string &new_password) {
    if (new_password.empty()) {
        throw std::invalid_argument("New password cannot be empty");
    }

    if (!isPasswordStrong(new_password)) {
        throw std::invalid_argument("Password does not meet strength requirements");
    }

    // Генерируем новую соль и хэшируем пароль
    salt = generateSalt();
    password_hash = hashWithSalt(new_password, salt);
}

// Проверка сложности пароля
bool MasterPasswordManager::isPasswordStrong(const std::string &password) {
    return hasMinimumLength(password, 12) &&
           hasUppercase(password) &&
           hasLowercase(password) &&
           hasDigits(password) &&
           hasSpecialChars(password) &&
           hasNoCommonPatterns(password) &&
           calculateEntropy(password) >= 80; // Высокая энтропия
}

// Получение обратной связи о сложности пароля
std::string MasterPasswordManager::getPasswordStrengthFeedback(const std::string &password) {
    std::vector<std::string> feedback;

    if (!hasMinimumLength(password, 12)) {
        feedback.push_back("Password should be at least 12 characters long");
    }

    if (!hasUppercase(password)) {
        feedback.push_back("Password should contain uppercase letters");
    }

    if (!hasLowercase(password)) {
        feedback.push_back("Password should contain lowercase letters");
    }

    if (!hasDigits(password)) {
        feedback.push_back("Password should contain digits");
    }

    if (!hasSpecialChars(password)) {
        feedback.push_back("Password should contain special characters");
    }

    if (!hasNoCommonPatterns(password)) {
        feedback.push_back("Password should not contain common patterns or words");
    }

    int entropy = calculateEntropy(password);
    if (entropy < 60) {
        feedback.push_back("Password is too predictable");
    } else if (entropy < 80) {
        feedback.push_back("Password could be stronger");
    }

    if (feedback.empty()) {
        return "Password is strong";
    }

    std::string result;
    for (size_t i = 0; i < feedback.size(); ++i) {
        result += std::to_string(i + 1) + ". " + feedback[i];
        if (i < feedback.size() - 1) {
            result += "\n";
        }
    }

    return result;
}

// Геттеры
std::string MasterPasswordManager::getPasswordHash() const {
    return password_hash;
}

std::vector<unsigned char> MasterPasswordManager::getSalt() const {
    return salt;
}

bool MasterPasswordManager::isPasswordSet() const {
    return !password_hash.empty();
}

// Генерация соли
std::vector<unsigned char> MasterPasswordManager::generateSalt() {
    std::vector<unsigned char> new_salt(SALT_LENGTH);
    if (RAND_bytes(new_salt.data(), SALT_LENGTH) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }
    return new_salt;
}

// Хэширование пароля с солью
std::string MasterPasswordManager::hashWithSalt(const std::string &password, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> derived_key = performPBKDF2(password, salt);

    // Формат: salt:hash (в Base64-like представлении)
    std::string salt_str = vectorToString(salt);
    std::string hash_str = vectorToString(derived_key);

    return salt_str + ":" + hash_str;
}

// Преобразование строки в вектор
std::vector<unsigned char> MasterPasswordManager::stringToVector(const std::string &str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

// Преобразование вектора в строку
std::string MasterPasswordManager::vectorToString(const std::vector<unsigned char> &vec) {
    return std::string(vec.begin(), vec.end());
}

// PBKDF2 для derivation ключа
std::vector<unsigned char>
MasterPasswordManager::performPBKDF2(const std::string &password, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> derived_key(HASH_LENGTH);

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          HASH_LENGTH, derived_key.data()) != 1) {
        throw std::runtime_error("Failed to derive key from password");
    }

    return derived_key;
}

// Сравнение с постоянным временем
bool MasterPasswordManager::constantTimeCompare(const std::string &a, const std::string &b) {
    if (a.length() != b.length()) {
        return false;
    }

    unsigned char result = 0;
    for (size_t i = 0; i < a.length(); ++i) {
        result |= a[i] ^ b[i];
    }

    return result == 0;
}

// Сериализация
std::string MasterPasswordManager::serialize() const {
    std::stringstream ss;
    ss << vectorToString(salt) << "\n" << password_hash;
    return ss.str();
}

// Десериализация
MasterPasswordManager MasterPasswordManager::deserialize(const std::string &data) {
    std::stringstream ss(data);
    std::string salt_str, hash;

    std::getline(ss, salt_str);
    std::getline(ss, hash);

    std::vector<unsigned char> salt_vec = stringToVector(salt_str);
    return MasterPasswordManager(hash, salt_vec);
}

// Очистка чувствительных данных
void MasterPasswordManager::clearSensitiveData() {
    // Перезаписываем чувствительные данные в памяти
    std::fill(password_hash.begin(), password_hash.end(), 0);
    std::fill(salt.begin(), salt.end(), 0);
    password_hash.clear();
    salt.clear();
}

// Проверки сложности пароля

bool MasterPasswordManager::hasMinimumLength(const std::string &password, size_t min_length) {
    return password.length() >= min_length;
}

bool MasterPasswordManager::hasUppercase(const std::string &password) {
    return std::any_of(password.begin(), password.end(), ::isupper);
}

bool MasterPasswordManager::hasLowercase(const std::string &password) {
    return std::any_of(password.begin(), password.end(), ::islower);
}

bool MasterPasswordManager::hasDigits(const std::string &password) {
    return std::any_of(password.begin(), password.end(), ::isdigit);
}

bool MasterPasswordManager::hasSpecialChars(const std::string &password) {
    return std::any_of(password.begin(), password.end(), [](char c) {
        return !std::isalnum(c) && !std::isspace(c);
    });
}

bool MasterPasswordManager::hasNoCommonPatterns(const std::string &password) {
    // Список common passwords и patterns
    static const std::vector<std::string> COMMON_PATTERNS = {
            "password", "123456", "qwerty", "admin", "welcome",
            "monkey", "letmein", "dragon", "baseball", "iloveyou",
            "trustno1", "sunshine", "master", "hello", "freedom"
    };

    std::string lower_password = password;
    std::transform(lower_password.begin(), lower_password.end(), lower_password.begin(), ::tolower);

    for (const auto &pattern: COMMON_PATTERNS) {
        if (lower_password.find(pattern) != std::string::npos) {
            return false;
        }
    }

    // Проверка на последовательности
    for (size_t i = 0; i < password.length() - 2; ++i) {
        if (std::isalpha(password[i]) && std::isalpha(password[i + 1]) && std::isalpha(password[i + 2])) {
            // Проверка последовательных букв (abc, def, etc.)
            if (password[i] + 1 == password[i + 1] && password[i + 1] + 1 == password[i + 2]) {
                return false;
            }
        }
        if (std::isdigit(password[i]) && std::isdigit(password[i + 1]) && std::isdigit(password[i + 2])) {
            // Проверка последовательных цифр (123, 456, etc.)
            if (password[i] + 1 == password[i + 1] && password[i + 1] + 1 == password[i + 2]) {
                return false;
            }
        }
    }

    return true;
}

// Расчет энтропии пароля
int MasterPasswordManager::calculateEntropy(const std::string &password) {
    if (password.empty()) return 0;

    // Определяем набор символов
    bool has_upper = hasUppercase(password);
    bool has_lower = hasLowercase(password);
    bool has_digit = hasDigits(password);
    bool has_special = hasSpecialChars(password);

    int charset_size = 0;
    if (has_upper) charset_size += 26;
    if (has_lower) charset_size += 26;
    if (has_digit) charset_size += 10;
    if (has_special) charset_size += 32; // Примерное количество специальных символов

    if (charset_size == 0) return 0;

    // Энтропия = log2(charset_size) * length
    double entropy = std::log2(charset_size) * password.length();
    return static_cast<int>(entropy);

}