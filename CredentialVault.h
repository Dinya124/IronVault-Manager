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
    explicit CredentialVault(const std::string& file_path);

    // Основные методы работы с хранилищем
    bool loadFromFile(const std::string& master_password);
    bool saveToFile(const std::string& master_password);
    bool verifyMasterPassword(const std::string& master_password) const;
    void lockVault();




};


#endif
