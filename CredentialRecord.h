#ifndef CREDENTIALRECORD_H
#define CREDENTIALRECORD_H

#include "BaseRecord.h"
#include <string>
#include <memory>

class CredentialRecord : public BaseRecord {
private:
    std::string service_name;
    std::string url;
    std::string login;
    std::string encrypted_password;
    std::string category;

public:
    // Конструктор по умолчанию
    CredentialRecord();

    // Параметризованный конструктор
    // Важно: принимаем std::string по значению для std::move (оптимизация)
    CredentialRecord(std::string service, std::string url,
                     std::string login, std::string encrypted_password,
                     std::string category);

    // --- Реализация виртуальных методов BaseRecord ---
    std::string getType() const override { return "Credential"; }

    // Краткая сводка для списков
    std::string getSummary() const override {
        return service_name + " (" + login + ")";
    }

    // Полная информация (с расшифровкой)
    std::string getDetailedInfo(const std::string& masterKey) const override;

    // Сериализация для сохранения
    std::string serialize() const override;

    // Клонирование объекта
    std::unique_ptr<BaseRecord> clone() const override;

    // --- Специфичные геттеры ---
    std::string getServiceName() const;
    std::string getUrl() const;
    std::string getLogin() const;
    std::string getCategory() const;
    std::string getEncryptedPassword() const;

    // --- Статический метод десериализации (Фабрика) ---
    static std::unique_ptr<CredentialRecord> deserializeObj(const std::string& data);
};

#endif