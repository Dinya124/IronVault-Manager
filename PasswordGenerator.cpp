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
// Сеттеры
void PasswordGenerator::setLength(int len) {
    if (len <= 0){
        throw  std::invalid_argument("Password length must be positive");
    }
    length = len;
}

void PasswordGenerator::setUppercase(bool use) {
    use_uppercase = use;
    validateSettings();
}

void PasswordGenerator::setLowercase(bool use) {
    use_lowercase = use;
    validateSettings();
}

void PasswordGenerator::setDigits(bool use) {
    use_digits = use;
    validateSettings();
}

void PasswordGenerator::setSpecialChars(bool use) {
    use_special_chars = use;
    validateSettings();
}
// Геттеры
int PasswordGenerator::getLength() const {return length;}
bool PasswordGenerator::getUppercase() const {return use_uppercase;}
bool PasswordGenerator::getLowercase() const {return  use_lowercase;}
bool PasswordGenerator::getDigits() const {return  use_digits;}
bool PasswordGenerator::getSpecialChars() const {return use_special_chars;}
