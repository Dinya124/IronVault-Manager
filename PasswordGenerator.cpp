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

std::string PasswordGenerator::generate() {
    validateSettings();
}

