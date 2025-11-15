#ifndef PASSWORDGENERATOR_H
#define PASSWORDGENERATOR_H

#include "string"
#include <random>

class PasswordGenerator {
private:
    int length; // длина пароля
    bool use_uppercase; // Использвать заглавные буквы
    bool use_lowercase; // Использвать строчные буквы
    bool use_digits; // Использват цифры
    bool use_special_chars; // Использовать спец символы
    std::mt19937 random_engine;   // генератор случайных чисел

public:
    PasswordGenerator(int len = 12,
                      bool uppercase = true,
                      bool lowercase = true,
                      bool digits = true,
                      bool special = false);

    std::string generate();

    // Настройка параметров
    void setLength(int len);

    void setUppercase(bool use);

    void setLowercase(bool use);

    void setDigits(bool use);

    void setSpecialChars(bool use);

    // Получение параметров
    int getLength() const;

    bool getUppercase() const;

    bool getLowercase() const;

    bool getDigits() const;

    bool getSpecialChars() const;

private:
    // Вспомогательные методы
    std::string getUpperChars() const;

    std::string getLowercaseChars() const;

    std::string getDigitChars() const;

    std::string getSpecialCharsSet() const;

    std::string getAllAvailableChars() const;

    void validateSettings() const;
};


#endif
