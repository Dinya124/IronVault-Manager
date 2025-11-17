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
