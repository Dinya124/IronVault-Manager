#ifndef BASERECORD_H
#define BASERECORD_H

#include <string>
#include <memory>
#include <ctime>

class BaseRecord {
protected:
    std::time_t last_modified;

public:
    BaseRecord() : last_modified(std::time(nullptr)) {}
    virtual ~BaseRecord() = default;

    // Чисто виртуальные методы (интерфейс)
    virtual std::string getType() const = 0;          // Например: "Credential", "BankCard"
    virtual std::string getSummary() const = 0;       // Для таблицы (например, "Google (my@email)")
    virtual std::string getDetailedInfo(const std::string& key) const = 0; // Полный текст для просмотра

    // Сериализация для сохранения в файл
    virtual std::string serialize() const = 0;


    virtual std::unique_ptr<BaseRecord> clone() const = 0;

    // Общие методы
    std::time_t getLastModified() const { return last_modified; }
    void updateLastModified() { last_modified = std::time(nullptr); }
};

#endif