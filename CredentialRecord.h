#ifndef CREDENTIALRECORD_H
#define CREDENTIALRECORD_H

#include <string>
#include <ctime>
#include <iostream>
#include "BaseRecord.h"

class CredentialRecord : public BaseRecord {
private:
    std::string service_name;
    std::string url;
    std::string login;
    std::string encrypted_password;
    std::string category;
    std::string internal_key;

    static int records_created_count;

public:
    CredentialRecord();

    CredentialRecord(const std::string &service, const std::string &url,
                     const std::string &login, const std::string &encrypted_password,
                     const std::string &category = "General");

    // Конструктор копирования (теперь обязателен для clone)
    CredentialRecord(const CredentialRecord& other);

    static int getRecordsCreatedCount();

    bool operator==(const CredentialRecord& other) const;
    bool operator!=(const CredentialRecord& other) const;
    friend std::ostream& operator<<(std::ostream& os, const CredentialRecord& record);

    std::string getPassword(const std::string &decryption_key) const;

    //Реализация виртуальных методов BaseRecord
    std::string getSummary() const override;
    std::string getType() const override { return "Credential"; }
    BaseRecord* clone() const override;


    // Сеттеры
    void setServiceName(const std::string &name);
    void setUrl(const std::string &url);
    void setLogin(const std::string &login);
    void setEncryptedPassword(const std::string &encrypted_password);
    void setCategory(const std::string &category);
    void setInternalKey(const std::string &key);

    // Геттеры
    std::string getServiceName() const;
    std::string getUrl() const;
    std::string getLogin() const;
    std::string getEncryptedPassword() const;
    std::string getCategory() const;
    std::string getInternalKey() const;

    bool isEmpty() const;
    std::string toString() const;

    std::string serialize() const;
    static CredentialRecord deserialize(const std::string &data);
};

#endif