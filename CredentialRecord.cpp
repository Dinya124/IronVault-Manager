#include "CredentialRecord.h"
#include "DataEncryption.h" // Важно подключить для decrypt
#include <sstream>
#include <vector>
#include <iomanip>
#include <iostream>
#include <stdexcept>

// Анонимное пространство имен для локальных помощников
namespace {
    const std::string DELIM = "|;|";

    // Безопасная кроссплатформенная функция времени
    void safe_localtime(const std::time_t& time, std::tm& tm_struct) {
#if defined(_MSC_VER) || defined(_WIN32)
        localtime_s(&tm_struct, &time);
#else
        localtime_r(&time, &tm_struct);
#endif
    }
}

// Вспомогательная функция split
static std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
    std::vector<std::string> tokens;
    if (s.empty()) return tokens;

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

// --- Конструкторы ---

CredentialRecord::CredentialRecord()
        : BaseRecord(),
          service_name("Unknown"), url(""), login(""), encrypted_password(""), category("General") {}

// Реализация конструктора (совпадает с заголовком: string по значению)
CredentialRecord::CredentialRecord(std::string service, std::string url,
                                   std::string login, std::string encrypted_password,
                                   std::string category)
        : BaseRecord(),
          service_name(std::move(service)),
          url(std::move(url)),
          login(std::move(login)),
          encrypted_password(std::move(encrypted_password)),
          category(std::move(category)) {

    if (this->service_name.empty()) {
        throw std::invalid_argument("Service name cannot be empty");
    }
    if (this->category.empty()) {
        this->category = "General";
    }
}

// --- Методы BaseRecord ---

std::unique_ptr<BaseRecord> CredentialRecord::clone() const {
    return std::make_unique<CredentialRecord>(*this);
}

std::string CredentialRecord::serialize() const {
    std::stringstream ss;
    ss << getType() << DELIM
       << service_name << DELIM
       << url << DELIM
       << login << DELIM
       << encrypted_password << DELIM
       << category << DELIM
       << last_modified;
    return ss.str();
}

std::string CredentialRecord::getDetailedInfo(const std::string &masterKey) const {
    std::stringstream ss;
    ss << "Тип:        Учетная запись\n";
    ss << "Сервис:     " << service_name << "\n";
    ss << "URL:        " << (url.empty() ? "-" : url) << "\n";
    ss << "Логин:      " << login << "\n";
    ss << "Категория:  " << category << "\n";

    std::tm tm_struct = {};
    safe_localtime(last_modified, tm_struct);
    ss << "Изменено:   " << std::put_time(&tm_struct, "%Y-%m-%d %H:%M:%S") << "\n";

    ss << "Пароль:     ";
    try {
        if (encrypted_password.empty()) {
            ss << "[ПУСТО]";
        } else {
            // Требует #include "DataEncryption.h"
            std::string decrypted = DataEncryption::decrypt(encrypted_password, masterKey);
            ss << decrypted;
        }
    } catch (...) {
        ss << "[ОШИБКА РАСШИФРОВКИ]";
    }

    return ss.str();
}

// --- Десериализация ---

std::unique_ptr<CredentialRecord> CredentialRecord::deserializeObj(const std::string& data) {
    if (data.empty()) return nullptr;

    std::vector<std::string> parts = split(data, DELIM);

    // Ожидаем минимум 7 полей
    if (parts.size() < 7) return nullptr;

    try {
        auto record = std::make_unique<CredentialRecord>(
                std::move(parts[1]),
                std::move(parts[2]),
                std::move(parts[3]),
                std::move(parts[4]),
                std::move(parts[5])
        );

        try {
            record->last_modified = std::stol(parts[6]);
        } catch (...) {
            record->last_modified = std::time(nullptr);
        }

        return record;
    } catch (...) {
        return nullptr;
    }
}

// --- Геттеры ---

std::string CredentialRecord::getServiceName() const { return service_name; }
std::string CredentialRecord::getUrl() const { return url; }
std::string CredentialRecord::getLogin() const { return login; }
std::string CredentialRecord::getCategory() const { return category; }
std::string CredentialRecord::getEncryptedPassword() const { return encrypted_password; }