#include "CredentialRecord.h"
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

// Сеттеры
void CredentialRecord::setServiceName(const std::string &name) {
    if (name.empty()) {
        throw std::invalid_argument("Service name cannot be empty");
    }
    service_name = name;
    updateLastModified();
}

void CredentialRecord::setUrl(const std::string &url) {
    this->url = url;
    updateLastModified();
}

void CredentialRecord::setLogin(const std::string &login) {
    if (login.empty()) {
        throw std::invalid_argument("Login cannot be empty");
    }
    this->login = login;
    updateLastModified();
}

void CredentialRecord::setEncryptedPassword(const std::string &encrypted_password) {
    this->encrypted_password = encrypted_password;
    updateLastModified();
}

void CredentialRecord::setCategory(const std::string &category) {
    this->category = category.empty() ? "General" : category;
    updateLastModified();
}

void CredentialRecord::setInternalKey(const std::string &key) {
    internal_key = key;
    updateLastModified();
}

// Геттеры
std::string CredentialRecord::getServiceName() const { return service_name; }

std::string CredentialRecord::getUrl() const { return url; }

std::string CredentialRecord::getLogin() const { return login; }

std::string CredentialRecord::getEncryptedPassword() const { return encrypted_password; }

std::string CredentialRecord::getCategory() const { return category; }

std::string CredentialRecord::getInternalKey() const { return internal_key; }

std::string CredentialRecord::getLastModified() const { return last_modified; }

// Проверка на путсую запсь
bool CredentialRecord::isEmpty() const {
    return service_name.empty() && login.empty();
}

// Строковое представление
std::string CredentialRecord::toString() const {
    std::stringstream ss;
    ss << "Service: " << service_name
       << "\nURL: " << url
       << "\nLogin: " << login
       << "\nCategory: " << category
       << "\nLast Modified: " << std::ctime(&last_modified);
    return ss.str();
}

// Сериализация для сохранения в файл
std::string CredentialRecord::serialize() const {
    std::stringstream ss;
    ss << service_name << "\n"
       << url << "\n"
       << login << "\n"
       << encrypted_password << "\n"
       << category << "\n"
       << internal_key << "\n"
       << last_modified;
    return ss.str();
}

// Десериализация из строки
CredentialRecord CredentialRecord::deserialize(const std::string& data) {
    std::stringstream ss(data);
    CredentialRecord record;

    std::getline(ss, record.service_name);
    std::getline(ss, record.url);
    std::getline(ss, record.login);
    std::getline(ss, record.encrypted_password);
    std::getline(ss, record.category);
    std::getline(ss, record.internal_key);

    std::string time_str;
    std::getline(ss, time_str);
    if (!time_str.empty()) {
        record.last_modified = std::stol(time_str);
    }

    return record;
}