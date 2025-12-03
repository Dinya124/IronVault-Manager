#include "CredentialVault.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

const std::string CredentialVault::VAULT_HEADER = "IRONVAULT";
const std::string CredentialVault::VAULT_VERSION = "2.0";

CredentialVault::CredentialVault() : vault_file_path("ironvault.dat"), is_authenticated(false) {
    initializePasswordGenerator();
}

CredentialVault::CredentialVault(const std::string& file_path) : vault_file_path(file_path), is_authenticated(false) {
    initializePasswordGenerator();
}

// Загрузка
bool CredentialVault::loadFromFile(const std::string& master_password) {
    if (master_password.empty()) return false;

    std::ifstream file(vault_file_path, std::ios::binary | std::ios::ate); // Открываем и идем в конец
    if (!file.is_open()) {
        // Файла нет - создаем новый
        master_password_hash = MasterPasswordManager::hashPassword(master_password);
        is_authenticated = true;
        records.clear();
        return true;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg); // Вернулись в начало

    if (size <= 0) return false;

    // Читаем ВЕСЬ файл в строку
    std::string encrypted_data(size, ' ');
    if (!file.read(&encrypted_data[0], size)) return false;
    file.close();

    try {
        // Расшифровываем
        std::string decrypted_data = decryptVaultData(encrypted_data, master_password);
        if (decrypted_data.empty()) return false;

        std::stringstream ss(decrypted_data);
        std::string line;

        // 1. Проверка заголовка
        std::getline(ss, line);
        // Удаляем \r если есть (для Windows)
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line != VAULT_HEADER) return false;

        // 2. Версия
        std::getline(ss, line);

        // 3. Хеш пароля
        std::getline(ss, master_password_hash);
        if (!master_password_hash.empty() && master_password_hash.back() == '\r') master_password_hash.pop_back();

        // 4. Записи
        records.clear();
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            CredentialRecord rec = CredentialRecord::deserialize(line);
            if (!rec.getServiceName().empty()) {
                records.push_back(rec);
            }
        }

        is_authenticated = true;
        sortRecords();
        return true;

    } catch (...) {
        return false;
    }
}

// Сохранение
bool CredentialVault::saveToFile(const std::string& master_password) {
    if (!is_authenticated) return false;

    // Бэкап
    std::ifstream src(vault_file_path, std::ios::binary);
    if (src.is_open()) {
        std::ofstream dst(vault_file_path + ".bak", std::ios::binary);
        dst << src.rdbuf();
    }

    try {
        std::stringstream ss;
        ss << VAULT_HEADER << "\n";
        ss << VAULT_VERSION << "\n";
        ss << master_password_hash << "\n";

        for (const auto& r : records) {
            ss << r.serialize() << "\n";
        }

        // Шифруем ВСЁ содержимое сразу
        std::string encrypted = encryptVaultData(ss.str(), master_password);

        std::ofstream file(vault_file_path, std::ios::binary);
        file.write(encrypted.c_str(), encrypted.size());
        return true;
    } catch (...) {
        return false;
    }
}

// Остальные методы (без изменений логики)
bool CredentialVault::verifyMasterPassword(const std::string& mp) const {
    return MasterPasswordManager::verifyPassword(mp, master_password_hash);
}

void CredentialVault::lockVault() { is_authenticated = false; records.clear(); master_password_hash.clear(); }

bool CredentialVault::addRecord(const CredentialRecord& record) {
    if (!is_authenticated) return false;
    if (!isServiceNameUnique(record.getServiceName())) return false;
    records.push_back(record);
    sortRecords();
    return true;
}

bool CredentialVault::updateRecord(const std::string& s, const CredentialRecord& r) {
    if (!is_authenticated) return false;
    for (auto& rec : records) {
        if (rec.getServiceName() == s) {
            rec = r; sortRecords(); return true;
        }
    }
    return false;
}

bool CredentialVault::removeRecord(const std::string& s) {
    if (!is_authenticated) return false;
    auto it = std::remove_if(records.begin(), records.end(), [&](const CredentialRecord& r){ return r.getServiceName() == s; });
    if (it != records.end()) { records.erase(it, records.end()); return true; }
    return false;
}

CredentialRecord* CredentialVault::findRecord(const std::string& s) {
    if (!is_authenticated) return nullptr;
    for (auto& r : records) if (r.getServiceName() == s) return &r;
    return nullptr;
}

std::vector<CredentialRecord> CredentialVault::searchRecords(const SearchFilter& f) const {
    if (!is_authenticated) return {};
    std::vector<CredentialRecord> res;
    for (const auto& r : records) if (f.matches(r)) res.push_back(r);
    return res;
}

std::vector<std::string> CredentialVault::getAllCategories() const {
    std::vector<std::string> c;
    for (const auto& r : records) c.push_back(r.getCategory());
    std::sort(c.begin(), c.end());
    c.erase(std::unique(c.begin(), c.end()), c.end());
    return c;
}

std::string CredentialVault::generatePassword(int l, bool u, bool lo, bool d, bool s) {
    if (!password_genera) initializePasswordGenerator();
    password_genera->setLength(l); password_genera->setUppercase(u);
    password_genera->setLowercase(lo); password_genera->setDigits(d); password_genera->setSpecialChars(s);
    return password_genera->generate();
}

std::vector<CredentialRecord> CredentialVault::getAllRecords() const { return records; }

bool CredentialVault::isServiceNameUnique(const std::string& n) const {
    for (const auto& r : records) if (r.getServiceName() == n) return false;
    return true;
}

bool CredentialVault::validateRecord(const CredentialRecord& r) const { return !r.isEmpty(); }

std::string CredentialVault::encryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::encrypt(data, pass);
}

std::string CredentialVault::decryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::decrypt(data, pass);
}

void CredentialVault::initializePasswordGenerator() { password_genera = std::make_unique<PasswordGenerator>(); }
void CredentialVault::sortRecords() {
    std::sort(records.begin(), records.end(), [](const CredentialRecord& a, const CredentialRecord& b){
        return a.getServiceName() < b.getServiceName();
    });
}
// Заглушки
bool CredentialVault::validateVaultHeader(const std::string&) const { return true; }
std::string CredentialVault::createVaultHeader() const { return ""; }
bool CredentialVault::backupVaultFile() const { return true; }
size_t CredentialVault::getRecordCount() const { return records.size(); }
size_t CredentialVault::getCategoryCount() const { return 0; }
std::time_t CredentialVault::getLastModified() const { return 0; }
std::string CredentialVault::getVaultFilePath() const { return vault_file_path; }
bool CredentialVault::isAuthenticated() const { return is_authenticated; }
std::vector<CredentialRecord> CredentialVault::getRecordsByCategory(const std::string&) const { return {}; }
bool CredentialVault::exportToCsv(const std::string&, const std::string&) const { return false; }
bool CredentialVault::importFromCsv(const std::string&, const std::string&) { return false; }
void CredentialVault::removeDuplicateRecords() {}