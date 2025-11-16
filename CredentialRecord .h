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

};

#endif