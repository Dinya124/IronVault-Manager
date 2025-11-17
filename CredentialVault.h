#ifndef IRONVAULT_MANAGER_CREDENTIALVAULT_H
#define IRONVAULT_MANAGER_CREDENTIALVAULT_H

#include "CredentialRecord.h"
#include "DataEncryption.h"
#include "MasterPasswordManager.h"
#include "PasswordGenerator.h"
#include "SearchFilter.h"
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <ctime>

class CredentialVault {
private:
    std::vector<CredentialRecord> records;
    std::string vault_file_path;
    std::string master_password_hash;
    bool is_authenticated;
    std::unique_ptr<PasswordGenerator> password_genera;


    // Константы
    static const std::string VAULT_HEADER;
    static const std::string VAULT_VERSION;

public:
    // Конструкторы
    CredentialVault();

    explicit CredentialVault(const std::string &file_path);

    // Основные методы работы с хранилищем
    bool loadFromFile(const std::string &master_password);

    bool saveToFile(const std::string &master_password);

    bool verifyMasterPassword(const std::string &master_password) const;

    void lockVault();

    // Управление записями
    bool addRecord(const CredentialRecord &record);

    bool updateRecord(const std::string &service_name, const CredentialRecord &updated_record);

    bool removeRecord(const std::string &service_name);

    CredentialRecord *findRecord(const std::string &service_name);

// Поиск и фильтрация
    std::vector<CredentialRecord> searchRecords(const SearchFilter &filter) const;

    std::vector<CredentialRecord> getRecordsByCategory(const std::string &category) const;

    std::vector<std::string> getAllCategories() const;

    // Генерация паролей
    std::string generatePassword(int length = 16,
                                 bool use_uppercase = true,
                                 bool use_lowercase = true,
                                 bool use_digits = true,
                                 bool use_special = true);

    // Статистика
    size_t getRecordCount() const;

    size_t getCategoryCount() const;

    std::time_t getLastModified() const;

    // Геттеры
    std::string getVaultFilePath() const;

    bool isAuthenticated() const;

    std::vector<CredentialRecord> getAllRecords() const;

    // Валидация
    bool isServiceNameUnique(const std::string &service_name) const;

    bool validateRecord(const CredentialRecord &record) const;

    // Импорт/экспорт
    bool exportToCsv(const std::string &file_path, const std::string &master_password) const;

    bool importFromCsv(const std::string &file_path, const std::string &master_password);

};


#endif
