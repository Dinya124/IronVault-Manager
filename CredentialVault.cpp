#include "CredentialVault.h"
#include "SecureRepository.h"
#include "VaultStatistics.h" // Шаблонная функция

#include <fstream>
#include <sstream>
#include <algorithm> // std::sort, std::find_if, std::transform
#include <iostream>
#include <iterator>  // std::back_inserter

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

    std::ifstream file(vault_file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        // Файла нет - создаем новый
        master_password_hash = MasterPasswordManager::hashPassword(master_password);
        is_authenticated = true;
        repository.clear();
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
        if (decrypted_data.empty()) return false;

        std::stringstream ss(decrypted_data);
        std::string line;

        // 1. Проверка заголовка
        std::getline(ss, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line != VAULT_HEADER) return false;

        // 2. Версия
        std::getline(ss, line);

        // 3. Хеш пароля
        std::getline(ss, master_password_hash);
        if (!master_password_hash.empty() && master_password_hash.back() == '\r') master_password_hash.pop_back();

        // 4. Записи -> Вставка в РЕПОЗИТОРИЙ
        repository.clear();
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            CredentialRecord rec = CredentialRecord::deserialize(line);
            if (!rec.getServiceName().empty()) {
                // Важно: устанавливаем описание для базового класса, чтобы репозиторий мог индексировать
                rec.setDescription(rec.getServiceName());
                repository.add(rec);
            }
        }

        is_authenticated = true;
        sortRecords(); // Использует std::sort внутри
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

        // Получаем доступ к хранилищу репозитория
        const auto& records_vec = repository.getStorage();

        // Итерация по shared_ptr
        for (const auto& ptr : records_vec) {
            ss << ptr->serialize() << "\n";
        }

        std::string encrypted = encryptVaultData(ss.str(), master_password);

        std::ofstream file(vault_file_path, std::ios::binary);
        file.write(encrypted.c_str(), encrypted.size());
        return true;
    } catch (...) {
        return false;
    }
}

bool CredentialVault::verifyMasterPassword(const std::string& mp) const {
    return MasterPasswordManager::verifyPassword(mp, master_password_hash);
}

void CredentialVault::lockVault() {
    is_authenticated = false;
    repository.clear();
    master_password_hash.clear();
}

bool CredentialVault::addRecord(const CredentialRecord& record) {
    if (!is_authenticated) return false;
    if (!isServiceNameUnique(record.getServiceName())) return false;

    // Копируем запись, чтобы установить описание для BaseRecord
    CredentialRecord rec_copy = record;
    rec_copy.setDescription(rec_copy.getServiceName());

    repository.add(rec_copy);
    sortRecords();
    return true;
}

bool CredentialVault::updateRecord(const std::string& s, const CredentialRecord& r) {
    if (!is_authenticated) return false;

    auto& vec = repository.getStorage();
    // STL Algorithm: find_if
    auto it = std::find_if(vec.begin(), vec.end(), [&](const std::shared_ptr<CredentialRecord>& ptr){
        return ptr->getServiceName() == s;
    });

    if (it != vec.end()) {
        **it = r; // Обновляем содержимое объекта по указателю
        (*it)->setDescription(r.getServiceName()); // Обновляем поле базового класса
        sortRecords();
        return true;
    }
    return false;
}

bool CredentialVault::removeRecord(const std::string& s) {
    if (!is_authenticated) return false;
    // Используем метод репозитория, который внутри использует std::remove_if
    return repository.removeByDescription(s);
}

CredentialRecord* CredentialVault::findRecord(const std::string& s) {
    if (!is_authenticated) return nullptr;

    auto& vec = repository.getStorage();
    // STL Algorithm: find_if
    auto it = std::find_if(vec.begin(), vec.end(), [&](const std::shared_ptr<CredentialRecord>& ptr){
        return ptr->getServiceName() == s;
    });

    if (it != vec.end()) {
        return it->get(); // Возвращаем сырой указатель
    }
    return nullptr;
}

std::vector<CredentialRecord> CredentialVault::searchRecords(const SearchFilter& f) const {
    if (!is_authenticated) return {};
    std::vector<CredentialRecord> res;

    const auto& vec = repository.getStorage();
    for (const auto& ptr : vec) {
        if (f.matches(*ptr)) {
            res.push_back(*ptr);
        }
    }
    return res;
}

std::vector<std::string> CredentialVault::getAllCategories() const {
    std::vector<std::string> c;
    const auto& vec = repository.getStorage();

    for (const auto& ptr : vec) {
        c.push_back(ptr->getCategory());
    }

    // STL Algorithms: sort + unique
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

std::vector<CredentialRecord> CredentialVault::getAllRecords() const {
    std::vector<CredentialRecord> result;
    const auto& vec = repository.getStorage();
    result.reserve(vec.size());

    for(const auto& ptr : vec) {
        result.push_back(*ptr);
    }
    return result;
}

bool CredentialVault::isServiceNameUnique(const std::string& n) const {
    const auto& vec = repository.getStorage();
    // STL Algorithm: none_of / any_of
    return std::none_of(vec.begin(), vec.end(), [&](const std::shared_ptr<CredentialRecord>& ptr){
        return ptr->getServiceName() == n;
    });
}

// Реализация сортировки с использованием STL
void CredentialVault::sortRecords() {
    auto& vec = repository.getStorage();
    // STL Algorithm: sort с лямбдой
    std::sort(vec.begin(), vec.end(), [](const std::shared_ptr<CredentialRecord>& a, const std::shared_ptr<CredentialRecord>& b){
        return a->getServiceName() < b->getServiceName();
    });
}

// --- НОВЫЙ МЕТОД: Расчет статистики с использованием шаблонной функции ---
[[maybe_unused]] double CredentialVault::calculateAverageEncryptionStrength() const {
    const auto& vec = repository.getStorage();
    if (vec.empty()) return 0.0;

    std::vector<int> lengths;
    lengths.reserve(vec.size());

    // STL Algorithm: transform
    // Преобразуем объекты записей в числа (длину зашифрованного пароля как простую метрику)
    std::transform(vec.begin(), vec.end(), std::back_inserter(lengths),
                   [](const std::shared_ptr<CredentialRecord>& ptr) {
                       return static_cast<int>(ptr->getEncryptedPassword().length());
                   }
    );

    // Вызов шаблонной функции из VaultStatistics.h
    return VaultStats::calculateAverage(lengths);
}

// Методы-заглушки и вспомогательные
bool CredentialVault::validateRecord(const CredentialRecord& r) const { return !r.isEmpty(); }
std::string CredentialVault::encryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::encrypt(data, pass);
}
std::string CredentialVault::decryptVaultData(const std::string& data, const std::string& pass) const {
    return DataEncryption::decrypt(data, pass);
}
void CredentialVault::initializePasswordGenerator() { password_genera = std::make_unique<PasswordGenerator>(); }
bool CredentialVault::validateVaultHeader(const std::string&) const { return true; }
std::string CredentialVault::createVaultHeader() const { return ""; }
bool CredentialVault::backupVaultFile() const { return true; }

// Получение количества через репозиторий
size_t CredentialVault::getRecordCount() const { return repository.count(); }

size_t CredentialVault::getCategoryCount() const { return getAllCategories().size(); }
std::time_t CredentialVault::getLastModified() const { return 0; }
std::string CredentialVault::getVaultFilePath() const { return vault_file_path; }
bool CredentialVault::isAuthenticated() const { return is_authenticated; }
std::vector<CredentialRecord> CredentialVault::getRecordsByCategory(const std::string&) const { return {}; }
bool CredentialVault::exportToCsv(const std::string&, const std::string&) const { return false; }
bool CredentialVault::importFromCsv(const std::string&, const std::string&) { return false; }
void CredentialVault::removeDuplicateRecords() {}