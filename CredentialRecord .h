#ifndef CREDENTIALRECORD_H
#define CREDENTIALRECORD_H

#include <string>
#include <ctime>

class CredentialRecord {
private:
    std::string service_name; // название сервиса
    std::string url; // URL-адрес сервиса
    std::string login; // логин
    std::string encrypted_password; // зашифрованный пароль
    std::string category; // категория
    std::string internal_key; // внутренний ключ для шифрования
    std::time_t last_modified; // дата последнего изменения



public:
    // Конструкторы
    CredentialRecord();

    CredentialRecord(const std::string &service, const std::string &url,
                     const std::string &login, const std::string &encrypted_password,
                     const std::string &category = "General");


    // Основные методы
    std::string getPassword(const std::string &decryption_key) const;// возвращает расшифрованный пароль
    void updateLastModified();

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

    std::time_t getLastModified() const;


};


#endif
