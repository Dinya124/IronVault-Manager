#include "BankCardRecord.h"
#include <sstream>

// Вызов конструктора базового класса с параметрами (BaseRecord(std::time...))
BankCardRecord::BankCardRecord(const std::string& num, const std::string& holder, int pin)
        : BaseRecord(std::time(nullptr)), card_number(num), card_holder(holder) {
    this->description = "Bank Card Details"; // Доступ к protected полю
    this->raw_pin_code = new int(pin); // Выделение памяти
}

// Глубокое копирование
BankCardRecord::BankCardRecord(const BankCardRecord& other)
        : BaseRecord(other), card_number(other.card_number), card_holder(other.card_holder) {
    // Выделяем новую память и копируем значение, а не адрес
    this->raw_pin_code = new int(*other.raw_pin_code);
}

BankCardRecord::~BankCardRecord() {
    delete raw_pin_code; // Очистка ресурса
}

// Перегрузка метода (реализация виртуального)
std::string BankCardRecord::getSummary() const {
    //Без вызова метода базового класса
    return "CARD: " + card_number + " (" + card_holder + ")";
}

BaseRecord* BankCardRecord::clone() const {
    // Вызывает конструктор копирования
    return new BankCardRecord(*this);
}

// Оператор присваивания Derived = Base
BankCardRecord& BankCardRecord::operator=(const BaseRecord& base) {
    if (this != &base) {
        // Копируем только общие поля из базы
        this->last_modified = base.getLastModified();
        // Специфичные поля оставляем как есть или обнуляем, т.к в Base их нет
    }
    return *this;
}



