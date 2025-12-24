#ifndef IRONVAULT_BASERECORD_H
#define IRONVAULT_BASERECORD_H

#include <string>
#include <ctime>

// Абстрактный класс (Интерфейс)
class BaseRecord {
protected:
    std::time_t last_modified;
    std::string description;

public:
    explicit BaseRecord(std::time_t modified = std::time(nullptr))
            : last_modified(modified), description("Generic Record") {}

    virtual ~BaseRecord() = default; // Виртуальный деструктор обязателен для полиморфизма

    // Чисто виртуальные методы
    virtual std::string getSummary() const = 0;
    virtual std::string getType() const = 0;
    virtual BaseRecord* clone() const = 0;

    std::time_t getLastModified() const { return last_modified; }
    void updateLastModified() { last_modified = std::time(nullptr); }

    void setDescription(const std::string& desc) { description = desc; }
    std::string getDescription() const { return description; }
};

#endif