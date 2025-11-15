#include "iostream"
#include "PasswordGenerator.h"
#include "stdexcept"

PasswordGenerator::PasswordGenerator(int len, bool uppercase, bool lowercase,
                                     bool digits, bool special)
        : length(len),
          use_uppercase(uppercase),
          use_lowercase(lowercase),
          use_digits(digits),
          use_special_chars(special) {

    std::random_device rd;
    random_engine = std::mt19937(rd());

    // Проверка корректности настроек
    validateSettings();
}

// Основной метод генерации пароля
std::string PasswordGenerator::generate() {
    validateSettings();
    std::string available_chars = getAllAvailableChars();
    if (available_chars.empty()) {
        throw std::runtime_error("No character sets selected"
                                 " for password generation");
    }
    std::string password;
    std::uniform_int_distribution<int> dist(0, available_chars.size() - 1);

    for (int i = 0; i < length; ++i) {
        int random_index = dist(random_engine);
        password += available_chars[random_index];
    }
    return  password;
}

