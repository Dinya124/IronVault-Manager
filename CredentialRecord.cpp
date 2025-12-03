#include "CredentialRecord.h"
#include <sstream>
#include <vector>
#include <iomanip>
#include "DataEncryption.h"

// Конструктор по умолчанию
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

    if (service_name.empty()) throw std::invalid_argument("Service name cannot be empty");
    if (login.empty()) throw std::invalid_argument("Login cannot be empty");
}

std::string CredentialRecord::getPassword(const std::string &decryption_key) const {
    return DataEncryption::decrypt(encrypted_password, decryption_key, internal_key);
}

void CredentialRecord::updateLastModified() { last_modified = std::time(nullptr); }

// Сеттеры
void CredentialRecord::setServiceName(const std::string &name) { service_name = name; updateLastModified(); }
void CredentialRecord::setUrl(const std::string &url) { this->url = url; updateLastModified(); }
void CredentialRecord::setLogin(const std::string &login) { this->login = login; updateLastModified(); }
void CredentialRecord::setEncryptedPassword(const std::string &p) { this->encrypted_password = p; updateLastModified(); }
void CredentialRecord::setCategory(const std::string &c) { this->category = c.empty() ? "General" : c; updateLastModified(); }
void CredentialRecord::setInternalKey(const std::string &key) { internal_key = key; updateLastModified(); }

// Геттеры
std::string CredentialRecord::getServiceName() const { return service_name; }
std::string CredentialRecord::getUrl() const { return url; }
std::string CredentialRecord::getLogin() const { return login; }
std::string CredentialRecord::getEncryptedPassword() const { return encrypted_password; }
std::string CredentialRecord::getCategory() const { return category; }
std::string CredentialRecord::getInternalKey() const { return internal_key; }
std::time_t CredentialRecord::getLastModified() const { return last_modified; }
bool CredentialRecord::isEmpty() const { return service_name.empty() && login.empty(); }

std::string CredentialRecord::toString() const {
    return service_name + " (" + login + ")";
}

// --- СЕРИАЛИЗАЦИЯ ---
// Используем уникальный разделитель, который вряд ли встретится в данных
static const std::string DELIM = "|;|";

std::string CredentialRecord::serialize() const {
    std::stringstream ss;
    ss << service_name << DELIM
       << url << DELIM
       << login << DELIM
       << encrypted_password << DELIM
       << category << DELIM
       << internal_key << DELIM
       << last_modified;
    return ss.str();
}

// Вспомогательная функция для разделения строки
std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token;
    std::string s_copy = s;
    while ((pos = s_copy.find(delimiter)) != std::string::npos) {
        token = s_copy.substr(0, pos);
        tokens.push_back(token);
        s_copy.erase(0, pos + delimiter.length());
    }
    tokens.push_back(s_copy);
    return tokens;
}

CredentialRecord CredentialRecord::deserialize(const std::string& data) {
    CredentialRecord record;
    if (data.empty()) return record;

    std::vector<std::string> parts = split(data, DELIM);

    // Проверяем, что есть хотя бы основные поля
    if (parts.size() >= 6) {
        record.service_name = parts[0];
        record.url = parts[1];
        record.login = parts[2];
        record.encrypted_password = parts[3];
        record.category = parts[4];
        record.internal_key = parts[5];

        if (parts.size() > 6) {
            try {
                record.last_modified = std::stol(parts[6]);
            } catch (...) {
                record.last_modified = std::time(nullptr);
            }
        }
    }
    return record;
}