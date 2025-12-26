#include "CredentialVault.h"
#include <fstream>
#include <sstream>

const std::string CredentialVault::VAULT_HEADER = "IRONVAULT_POLY_2.0";

CredentialVault::CredentialVault(const std::string& file_path)
        : vault_file_path(file_path), is_authenticated(false) {
    initializePasswordGenerator();
}

bool CredentialVault::loadFromFile(const std::string& master_password) {
    if (master_password.empty()) return false;

    std::ifstream file(vault_file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        master_password_hash = MasterPasswordManager::hashPassword(master_password);
        is_authenticated = true;
        records.clear();
        return true;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size <= 0) return false;

    std::string encrypted_data(size, ' ');
    if (!file.read(&encrypted_data[0], size)) return false;
    file.close();

    try {
        std::string decrypted_data = decryptVaultData(encrypted_data, master_password);
        std::stringstream ss(decrypted_data);
        std::string line;

        std::getline(ss, line); // Header
        if (line.find("IRONVAULT") == std::string::npos) return false;

        std::getline(ss, line); // Skip version or extra header
        std::getline(ss, master_password_hash); // Hash

        records.clear();
        while (std::getline(ss, line)) {
            if (line.empty()) continue;

            // Определяем тип записи по префиксу строки
            // Строка выглядит так: "Credential|;|Google|;|..."
            if (line.find("Credential") == 0) {
                auto rec = CredentialRecord::deserializeObj(line);
                if (rec) records.push_back(std::move(rec));
            }
            // Сюда можно добавить else if (line.find("BankCard") == 0) ...
        }

        is_authenticated = true;
        return true;
    } catch (...) {
        return false;
    }
}

bool CredentialVault::saveToFile(const std::string& master_password) {
    if (!is_authenticated) return false;
    std::stringstream ss;
    ss << VAULT_HEADER << "\n2.0\n" << master_password_hash << "\n";

    // Полиморфный вызов serialize()
    for (const auto& rec : records) {
        ss << rec->serialize() << "\n";
    }

    try {
        std::string encrypted = encryptVaultData(ss.str(), master_password);
        std::ofstream file(vault_file_path, std::ios::binary);
        file.write(encrypted.c_str(), encrypted.size());
        return true;
    } catch (...) { return false; }
}

bool CredentialVault::addRecord(std::unique_ptr<BaseRecord> record) {
    if (!is_authenticated || !record) return false;

    // Проверка уникальности (нужен dynamic_cast, если проверяем конкретно Credential)
    if (auto* cred = dynamic_cast<CredentialRecord*>(record.get())) {
        if (!isServiceNameUnique(cred->getServiceName())) return false;
    }

    records.push_back(std::move(record));
    return true;
}

std::vector<const BaseRecord*> CredentialVault::getAllRecords() const {
    std::vector<const BaseRecord*> result;
    for (const auto& ptr : records) {
        result.push_back(ptr.get());
    }
    return result;
}

std::vector<const BaseRecord*> CredentialVault::searchRecords(const SearchFilter& f) const {
    std::vector<const BaseRecord*> res;
    for (const auto& ptr : records) {
        // Приведение типов для поиска по полям Credential
        if (auto* cred = dynamic_cast<const CredentialRecord*>(ptr.get())) {
            if (f.matches(*cred)) { // SearchFilter нужно адаптировать или оставить как есть
                res.push_back(ptr.get());
            }
        }
        // Для других типов записей можно добавить свои условия
    }
    return res;
}

// Остальные методы (helpers)
bool CredentialVault::verifyMasterPassword(const std::string& mp) const {
    return MasterPasswordManager::verifyPassword(mp, master_password_hash);
}
std::string CredentialVault::encryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::encrypt(data, pass);
}
std::string CredentialVault::decryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::decrypt(data, pass);
}
void CredentialVault::initializePasswordGenerator() {
    password_genera = std::make_unique<PasswordGenerator>();
}
bool CredentialVault::isServiceNameUnique(const std::string& n) const {
    for (const auto& ptr : records) {
        if (auto* cred = dynamic_cast<const CredentialRecord*>(ptr.get())) {
            if (cred->getServiceName() == n) return false;
        }
    }
    return true;
}
std::string CredentialVault::generatePassword(int l, bool u, bool lo, bool d, bool s) {
    if(!password_genera) initializePasswordGenerator();
    // Настройка генератора...
    return password_genera->generate();
}
std::vector<std::string> CredentialVault::getAllCategories() const {
    std::vector<std::string> cats;
    for(const auto& ptr : records) {
        if (auto* cred = dynamic_cast<const CredentialRecord*>(ptr.get())) {
            cats.push_back(cred->getCategory());
        }
    }
    std::sort(cats.begin(), cats.end());
    cats.erase(std::unique(cats.begin(), cats.end()), cats.end());
    return cats;
}