#include "CredentialVault.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <iostream>
#include <iomanip>

// Инициализация статических констант
const std::string CredentialVault::VAULT_HEADER = "IRONVAULT";
const std::string CredentialVault::VAULT_VERSION = "1.0";


// Конструктор по умолчанию
CredentialVault::CredentialVault()
        : vault_file_path("ironvault.dat"),
          master_password_hash(""),
          is_authenticated(false) {
    initializePasswordGenerator();
}

// Конструктор с путем к файлу
CredentialVault::CredentialVault(const std::string& file_path)
        : vault_file_path(file_path),
          master_password_hash(""),
          is_authenticated(false) {
    initializePasswordGenerator();
}
// Загрузка хранилища из файла
bool CredentialVault::loadFromFile(const std::string& master_password) {
    if (master_password.empty()) {
        throw std::invalid_argument("Master password cannot be empty");
    }

    std::ifstream file(vault_file_path, std::ios::binary);
    if (!file.is_open()) {
        // Файл не существует - создаем новое хранилище
        master_password_hash = MasterPasswordManager::hashPassword(master_password);
        is_authenticated = true;
        return true;
    }
    try {
        // Читаем зашифрованные данные
        std::stringstream encrypted_buffer;
        encrypted_buffer << file.rdbuf();
        file.close();

        std::string encrypted_data = encrypted_buffer.str();
        if (encrypted_data.empty()) {
            throw std::runtime_error("Vault file is empty or corrupted");
        }

        // Дешифруем данные
        std::string decrypted_data = decryptVaultData(encrypted_data, master_password);
        / Проверяем заголовок
        if (!validateVaultHeader(decrypted_data)) {
            throw std::runtime_error("Invalid vault file format");
        }

        // Парсим данные
        std::stringstream data_stream(decrypted_data);
        std::string line;

        // Пропускаем заголовок
        std::getline(data_stream, line); // header
        std::getline(data_stream, line); // version
        std::getline(data_stream, master_password_hash);

        // Читаем записи
        records.clear();
        while (std::getline(data_stream, line)) {
            if (line == "---RECORD---") {
                std::string record_data;
                while (std::getline(data_stream, line) && line != "---END_RECORD---") {
                    record_data += line + "\n";
                }
                if (!record_data.empty()) {
                    try {
                        CredentialRecord record = CredentialRecord::deserialize(record_data);
                        records.push_back(record);
                    } catch (const std::exception& e) {
                        std::cerr << "Warning: Failed to parse record: " << e.what() << std::endl;
                    }
                }
            }
        }

        is_authenticated = true;
        sortRecords();
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Failed to load vault: " << e.what() << std::endl;
        is_authenticated = false;
        return false;
    }
}

// Сохранение хранилища в файл
bool CredentialVault::saveToFile(const std::string& master_password) {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }
    if (master_password.empty()) {
        throw std::invalid_argument("Master password cannot be empty");
    }

    // Создаем резервную копию
    backupVaultFile();

    try {
        // Формируем данные для сохранения
        std::stringstream data_stream;
        data_stream << createVaultHeader();
        data_stream << master_password_hash << "\n";

        // Сериализуем записи
        for (const auto& record : records) {
            data_stream << "---RECORD---\n";
            data_stream << record.serialize();
            data_stream << "---END_RECORD---\n";
        }

        std::string data = data_stream.str();
        std::string encrypted_data = encryptVaultData(data, master_password);

        // Сохраняем в файл
        std::ofstream file(vault_file_path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open vault file for writing");
        }

        file << encrypted_data;
        file.close();

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Failed to save vault: " << e.what() << std::endl;
        return false;
    }
}

// Проверка мастер-пароля
bool CredentialVault::verifyMasterPassword(const std::string& master_password) const {
    return MasterPasswordManager::verifyPassword(master_password, master_password_hash);
}

// Блокировка хранилища
void CredentialVault::lockVault() {
    is_authenticated = false;
    // Очищаем чувствительные данные из памяти
    records.clear();
    master_password_hash.clear();
}

// Добавление записи
bool CredentialVault::addRecord(const CredentialRecord& record) {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }

    if (!validateRecord(record)) {
        return false;
    }

    if (!isServiceNameUnique(record.getServiceName())) {
        throw std::invalid_argument("Service name must be unique");
    }

    records.push_back(record);
    sortRecords();
    return true;
}

// Обновление записи
bool CredentialVault::updateRecord(const std::string& service_name, const CredentialRecord& updated_record) {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }

    for (auto& record : records) {
        if (record.getServiceName() == service_name) {
            // Проверяем уникальность нового имени сервиса (если оно изменилось)
            if (service_name != updated_record.getServiceName() &&
                !isServiceNameUnique(updated_record.getServiceName())) {
                throw std::invalid_argument("Service name must be unique");
            }

            record = updated_record;
            sortRecords();
            return true;
        }
    }

    return false;
}

// Удаление записи
bool CredentialVault::removeRecord(const std::string& service_name) {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }

    auto it = std::remove_if(records.begin(), records.end(),
                             [&service_name](const CredentialRecord& record) {
                                 return record.getServiceName() == service_name;
                             });

    if (it != records.end()) {
        records.erase(it, records.end());
        return true;
    }

    return false;
}

// Поиск записи по имени сервиса
CredentialRecord* CredentialVault::findRecord(const std::string& service_name) {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }

    for (auto& record : records) {
        if (record.getServiceName() == service_name) {
            return &record;
        }
    }

    return nullptr;
}

// Поиск записей по фильтру
std::vector<CredentialRecord> CredentialVault::searchRecords(const SearchFilter& filter) const {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }

    std::vector<CredentialRecord> results;
    for (const auto& record : records) {
        if (filter.matches(record)) {
            results.push_back(record);
        }
    }
    return results;
}

// Получение записей по категории
std::vector<CredentialRecord> CredentialVault::getRecordsByCategory(const std::string& category) const {
    SearchFilter filter;
    filter.setCategoryQuery(category);
    return searchRecords(filter);
}

// Получение всех категорий
std::vector<std::string> CredentialVault::getAllCategories() const {
    std::vector<std::string> categories;
    for (const auto& record : records) {
        categories.push_back(record.getCategory());
    }

    // Удаляем дубликаты
    std::sort(categories.begin(), categories.end());
    categories.erase(std::unique(categories.begin(), categories.end()), categories.end());

    return categories;
}
// Генерация пароля
std::string CredentialVault::generatePassword(int length, bool use_uppercase,
                                              bool use_lowercase, bool use_digits,
                                              bool use_special) {
    if (!password_generator) {
        initializePasswordGenerator();
    }

    password_generator->setLength(length);
    password_generator->setUppercase(use_uppercase);
    password_generator->setLowercase(use_lowercase);
    password_generator->setDigits(use_digits);
    password_generator->setSpecialChars(use_special);

    return password_generator->generate();
}

// Статистика
size_t CredentialVault::getRecordCount() const {
    return records.size();
}

size_t CredentialVault::getCategoryCount() const {
    return getAllCategories().size();
}

std::time_t CredentialVault::getLastModified() const {
    if (records.empty()) {
        return std::time(nullptr);
    }

    std::time_t last_modified = 0;
    for (const auto& record : records) {
        if (record.getLastModified() > last_modified) {
            last_modified = record.getLastModified();
        }
    }

    return last_modified;
}

// Геттеры
std::string CredentialVault::getVaultFilePath() const { return vault_file_path; }
bool CredentialVault::isAuthenticated() const { return is_authenticated; }
std::vector<CredentialRecord> CredentialVault::getAllRecords() const {
    if (!is_authenticated) {
        throw std::runtime_error("Vault is not authenticated");
    }
    return records;
}

// Валидация уникальности имени сервиса
bool CredentialVault::isServiceNameUnique(const std::string& service_name) const {
    for (const auto& record : records) {
        if (record.getServiceName() == service_name) {
            return false;
        }
    }
    return true;
}

// Валидация записи
bool CredentialVault::validateRecord(const CredentialRecord& record) const {
    return !record.isEmpty() &&
           !record.getServiceName().empty() &&
           !record.getLogin().empty();
}