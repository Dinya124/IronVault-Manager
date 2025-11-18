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

    explicit MasterPasswordManager(const std::string &stored_hash, const std::vector<unsigned char> &salt);

    // Основные методы
    static std::string hashPassword(const std::string &password);

    static bool verifyPassword(const std::string &password, const std::string &stored_hash);

    bool setNewPassword(const std::string &old_password, const std::string &new_password);

    void forceSetNewPassword(const std::string &new_password);

    // Проверка сложности пароля
    static bool isPasswordStrong(const std::string &password);

    static std::string getPasswordStrengthFeedback(const std::string &password);

    // Геттеры
    std::string getPasswordHash() const;

    std::vector<unsigned char> getSalt() const;

    bool isPasswordSet() const;

    // Статические утилиты
    static std::vector<unsigned char> generateSalt();

    static std::string hashWithSalt(const std::string &password, const std::vector<unsigned char> &salt);

    static std::vector<unsigned char> stringToVector(const std::string &str);

    static std::string vectorToString(const std::vector<unsigned char> &vec);

// Сериализация/десериализация
    std::string serialize() const;

    static MasterPasswordManager deserialize(const std::string &data);

    // Очистка чувствительных данных
    void clearSensitiveData();

private:
    // Внутренние методы
    static std::vector<unsigned char>
    performPBKDF2(const std::string &password, const std::vector<unsigned char> &salt);

    static bool constantTimeCompare(const std::string &a, const std::string &b);

    // Проверки сложности пароля
    static bool hasMinimumLength(const std::string &password, size_t min_length = 8);

    static bool hasUppercase(const std::string &password);

    static bool hasLowercase(const std::string &password);

    static bool hasDigits(const std::string &password);

    static bool hasSpecialChars(const std::string &password);

    static bool hasNoCommonPatterns(const std::string &password);

    static int calculateEntropy(const std::string &password);
};


#endif //IRONVAULT_MANAGER_MASTERPASSWORDMANAGER_H
