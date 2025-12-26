#ifndef CREDENTIALVAULT_H
#define CREDENTIALVAULT_H

#include "BaseRecord.h"
#include "CredentialRecord.h"
#include "DataEncryption.h"
#include "MasterPasswordManager.h"
#include "PasswordGenerator.h"
#include "SearchFilter.h"

#include <vector>
#include <string>
#include <memory>
#include <algorithm>

class CredentialVault {
private:
    // ПОЛИМОРФНЫЙ КОНТЕЙНЕР: хранит указатели на базовый класс
    std::vector<std::unique_ptr<BaseRecord>> records;

    std::string vault_file_path;
    std::string master_password_hash;
    bool is_authenticated;
    std::unique_ptr<PasswordGenerator> password_genera;

    static const std::string VAULT_HEADER;

public:
    CredentialVault(const std::string &file_path = "ironvault.dat");

    bool loadFromFile(const std::string &master_password);
    bool saveToFile(const std::string &master_password);

    // Добавление принимает unique_ptr (передача владения)
    bool addRecord(std::unique_ptr<BaseRecord> record);

    // Получение всех записей (возвращаем сырые указатели для просмотра)
    std::vector<const BaseRecord*> getAllRecords() const;

    // Поиск возвращает список указателей
    std::vector<const BaseRecord*> searchRecords(const SearchFilter &filter) const;

    // Вспомогательные
    std::vector<std::string> getAllCategories() const;
    std::string generatePassword(int len=16, bool u=true, bool l=true, bool d=true, bool s=true);
    bool isServiceNameUnique(const std::string &name) const;

    // Прочее
    bool verifyMasterPassword(const std::string &mp) const;
    bool isAuthenticated() const { return is_authenticated; }

private:
    std::string encryptVaultData(const std::string &data, const std::string &pass) const;
    std::string decryptVaultData(const std::string &data, const std::string &pass) const;
    void initializePasswordGenerator();
};

#endif