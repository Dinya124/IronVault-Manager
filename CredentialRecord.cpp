#include "CredentialRecord.h"
#include <sstream>
#include <vector>
#include <iomanip>
#include "DataEncryption.h"

int CredentialRecord::records_created_count = 0;

CredentialRecord::CredentialRecord()
        : BaseRecord(), // Вызов конструктора BaseRecord
          service_name(""), url(""), login(""), encrypted_password(""),
          category("General"), internal_key("") {
    records_created_count++;
}

CredentialRecord::CredentialRecord(const std::string &service, const std::string &url,
                                   const std::string &login, const std::string &encrypted_password,
                                   const std::string &category)
        : BaseRecord(std::time(nullptr)),
          service_name(service), url(url), login(login),
          encrypted_password(encrypted_password), category(category),
          internal_key("") {

    if (service_name.empty()) throw std::invalid_argument("Service name cannot be empty");
    if (login.empty()) throw std::invalid_argument("Login cannot be empty");

    this->description = "Login Credential"; // Поле из BaseRecord
    records_created_count++;
}

// Реализация конструктора копирования
CredentialRecord::CredentialRecord(const CredentialRecord& other)
        : BaseRecord(other), // Копирование базовой части
          service_name(other.service_name),
          url(other.url),
          login(other.login),
          encrypted_password(other.encrypted_password),
          category(other.category),
          internal_key(other.internal_key) {
    records_created_count++;
}

//Реализация виртуальных методов

std::string CredentialRecord::getSummary() const {
    // Перегрузка метода базового класса (реализация чисто виртуального)
    return service_name + " (" + login + ")";
}

BaseRecord* CredentialRecord::clone() const {
    // Клонирование: создает новую копию текущего объекта
    return new CredentialRecord(*this);
}


int CredentialRecord::getRecordsCreatedCount() { return records_created_count; }

bool CredentialRecord::operator==(const CredentialRecord& other) const {
    return this->service_name == other.service_name && this->login == other.login;
}

bool CredentialRecord::operator!=(const CredentialRecord& other) const { return !(*this == other); }

std::ostream& operator<<(std::ostream& os, const CredentialRecord& record) {
    os << "Service: " << record.service_name
       << " | Login: " << record.login
       << " | Category: " << record.category;
    return os;
}

std::string CredentialRecord::getPassword(const std::string &decryption_key) const {
    return DataEncryption::decrypt(encrypted_password, decryption_key, internal_key);
}

void CredentialRecord::setServiceName(const std::string &name) {
    if (this->service_name != name) {
        this->service_name = name;
        this->updateLastModified();
    }
}

void CredentialRecord::setUrl(const std::string &url) { this->url = url; updateLastModified(); }
void CredentialRecord::setLogin(const std::string &login) { this->login = login; updateLastModified(); }
void CredentialRecord::setEncryptedPassword(const std::string &p) { this->encrypted_password = p; updateLastModified(); }
void CredentialRecord::setCategory(const std::string &c) { this->category = c.empty() ? "General" : c; updateLastModified(); }
void CredentialRecord::setInternalKey(const std::string &key) { internal_key = key; updateLastModified(); }

std::string CredentialRecord::getServiceName() const { return service_name; }
std::string CredentialRecord::getUrl() const { return url; }
std::string CredentialRecord::getLogin() const { return login; }
std::string CredentialRecord::getEncryptedPassword() const { return encrypted_password; }
std::string CredentialRecord::getCategory() const { return category; }
std::string CredentialRecord::getInternalKey() const { return internal_key; }
bool CredentialRecord::isEmpty() const { return service_name.empty() && login.empty(); }

std::string CredentialRecord::toString() const {
    return service_name + " (" + login + ")";
}

static const std::string DELIM = "|;|";

std::string CredentialRecord::serialize() const {
    std::stringstream ss;
    ss << service_name << DELIM << url << DELIM << login << DELIM
       << encrypted_password << DELIM << category << DELIM << internal_key << DELIM << last_modified;
    return ss.str();
}

std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token, s_copy = s;
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
    if (parts.size() >= 6) {
        record.service_name = parts[0];
        record.url = parts[1];
        record.login = parts[2];
        record.encrypted_password = parts[3];
        record.category = parts[4];
        record.internal_key = parts[5];
        if (parts.size() > 6) {
            try { record.last_modified = std::stol(parts[6]); } catch (...) { record.last_modified = std::time(nullptr); }
        }
    }
    return record;
}