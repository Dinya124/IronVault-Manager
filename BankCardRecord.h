#ifndef BANKCARDRECORD_H
#define BANKCARDRECORD_H

#include "BaseRecord.h"
#include <string>

// Производный класс
class BankCardRecord : public BaseRecord {
private:
    std::string card_number;
    std::string card_holder;
    // Используем raw pointer чтобы показать разницу между поверхностным и глубоким копированием
    int* raw_pin_code;

public:
    BankCardRecord(const std::string& num, const std::string& holder, int pin);

    // Конструктор копирования (Глубокое копирование)
    BankCardRecord(const BankCardRecord& other);

    ~BankCardRecord() override;

    // Переопределение виртуальных методов
    std::string getSummary() const override;
    std::string getType() const override { return "BankCard"; }

    // Клонирование
    BaseRecord* clone() const override;

    // Перегрузка присваивания (Derived = Base)
    BankCardRecord& operator=(const BaseRecord& base);

    // Геттер для демонстрации
    int getPin() const { return *raw_pin_code; }
    void setPin(int p) { *raw_pin_code = p; }
};

#endif