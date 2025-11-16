#include "CredentialRecord .h"
#include "sstream"
#include "iomanip"
#include "stdexcept"

//Конструктор
CredentialRecord::CredentialRecord()
        : service_name(""), url(""), login(""), encrypted_password(""),
          category("General"), internal_key(""), last_modified(std::time(nullptr)) {}


// Параметризованный конструктор
CredentialRecord::CredentialRecord(const std::string &service, const std::string &url,
                                   const std::string &login, const std::string &encrypted_password,
                                   const std::string &category)
        : service_name(service), url(url), login(login),
          encrypted_password(encrypted_password), category(category),
          internal_key(""), last_modified(std::time(nullptr)) {

    if (service_name.empty()) {
        throw std::invalid_argument("Service name cannot be empty");
    }
    if (login.empty()) {
        throw std::invalid_argument("Login cannot be empty");
    }
}

// Основной метод - возвращает расшифорованный пароль
std::string CredentialRecord::getPassword(const std::string &decryption_key) const {
    return DataEncryption::decrypt(encrypted_password, decryption_key, internal_key);
}

// Обновление времени последнего изменения
void CredentialRecord::updateLastModified() {
    last_modified = std::time(nullptr);
}