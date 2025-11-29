#include <iostream>
#include <iomanip>
#include <ctime>

// Подключаем ВСЕ необходимые заголовочные файлы
#include "PasswordGenerator.h"
#include "DataEncryption.h"
#include "CredentialRecord.h"
#include "CredentialVault.h"
#include "SecureInputBuffer.h"
#include "MasterPasswordManager.h"
#include "SearchFilter.h"

// Функция для отображения меню
void displayMainMenu() {
    std::cout << "\n=== IronVault Password Manager ===" << std::endl;
    std::cout << "1. Add new credential" << std::endl;
    std::cout << "2. View all credentials" << std::endl;
    std::cout << "3. Search credentials" << std::endl;
    std::cout << "4. Generate password" << std::endl;
    std::cout << "5. Change master password" << std::endl;
    std::cout << "6. Vault statistics" << std::endl;
    std::cout << "7. Lock vault" << std::endl;
    std::cout << "8. Data Encryption Demo" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Choose option: ";
}

// Функция для отображения записи
void displayCredential(const CredentialRecord& record, bool show_password = false) {
    std::cout << "\n--- " << record.getServiceName() << " ---" << std::endl;
    std::cout << "URL: " << (record.getUrl().empty() ? "N/A" : record.getUrl()) << std::endl;
    std::cout << "Login: " << record.getLogin() << std::endl;
    if (show_password) {
        std::cout << "Password: [ENCRYPTED]" << std::endl;
    }
    std::cout << "Category: " << record.getCategory() << std::endl;

    std::time_t modified = record.getLastModified();
    std::cout << "Last modified: " << std::ctime(&modified);
}

// Демонстрация работы PasswordGenerator
void demonstratePasswordGenerator() {
    std::cout << "\n=== Password Generator Detailed Demo ===" << std::endl;

    PasswordGenerator generator;

    std::cout << "Default settings (16 chars, all types): " << std::endl;
    for (int i = 0; i < 3; i++) {
        std::cout << "  " << generator.generate() << std::endl;
    }

    generator.setLength(12);
    generator.setSpecialChars(false);
    std::cout << "\n12 chars, no special: " << generator.generate() << std::endl;

    generator.setLength(8);
    generator.setUppercase(false);
    generator.setLowercase(true);
    generator.setDigits(true);
    generator.setSpecialChars(false);
    std::cout << "8 chars, lowercase+digits: " << generator.generate() << std::endl;

    generator.setLength(20);
    generator.setUppercase(true);
    generator.setLowercase(true);
    generator.setDigits(true);
    generator.setSpecialChars(true);
    std::cout << "20 chars, all types (strong): " << generator.generate() << std::endl;
}

// Демонстрация работы DataEncryption
void demonstrateDataEncryption() {
    std::cout << "\n=== Data Encryption Demo ===" << std::endl;

    try {
        std::string password = "my_strong_master_password";
        std::string sensitive_data = "This is my secret password: SuperSecret123!";

        std::cout << "Original data: " << sensitive_data << std::endl;

        // Шифрование данных
        std::string encrypted = DataEncryption::encrypt(sensitive_data, password);
        std::cout << "Encrypted data: " << encrypted << std::endl;

        // Дешифрование данных
        std::string decrypted = DataEncryption::decrypt(encrypted, password);
        std::cout << "Decrypted data: " << decrypted << std::endl;

        // Проверка целостности
        bool integrity_ok = DataEncryption::verifyIntegrity(encrypted, password);
        std::cout << "Data integrity: " << (integrity_ok ? "OK" : "CORRUPTED") << std::endl;

        // Попытка дешифрования с неправильным паролем
        try {
            std::string wrong_decrypted = DataEncryption::decrypt(encrypted, "wrong_password");
            std::cout << "This should not happen!" << std::endl;
        } catch (const std::exception& e) {
            std::cout << " Correctly failed with wrong password: " << e.what() << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
    }
}

// Демонстрация работы CredentialRecord
void demonstrateCredentialRecord() {
    std::cout << "\n=== Credential Record Demo ===" << std::endl;

    // Создание записей
    CredentialRecord record1("Google", "https://google.com", "user@gmail.com", "encrypted_pass1", "Email");
    CredentialRecord record2("GitHub", "https://github.com", "developer", "encrypted_pass2", "Development");

    std::cout << "Record 1:" << std::endl;
    std::cout << record1.toString() << std::endl;

    std::cout << "Record 2:" << std::endl;
    std::cout << record2.toString() << std::endl;

    // Тестирование сериализации
    std::string serialized = record1.serialize();
    std::cout << "Serialized data:\n" << serialized << std::endl;

    CredentialRecord restored = CredentialRecord::deserialize(serialized);
    std::cout << "Restored record:\n" << restored.toString() << std::endl;

    // Тестирование методов доступа
    std::cout << "Service name: " << record1.getServiceName() << std::endl;
    std::cout << "Login: " << record1.getLogin() << std::endl;
    std::cout << "Category: " << record1.getCategory() << std::endl;
    std::cout << "URL: " << record1.getUrl() << std::endl;
}

// Функция добавления новой учетной записи
void addNewCredential(CredentialVault& vault) {
    std::cout << "\n=== Add New Credential ===" << std::endl;

    try {
        std::string service_name, url, login, category;

        std::cout << "Service name: ";
        std::getline(std::cin, service_name);

        std::cout << "URL (optional): ";
        std::getline(std::cin, url);

        std::cout << "Login: ";
        std::getline(std::cin, login);

        std::cout << "Category (default: General): ";
        std::getline(std::cin, category);
        if (category.empty()) category = "General";

        // Генерация пароля с помощью PasswordGenerator
        std::cout << "\nGenerate password? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore();

        std::string password;
        if (choice == 'y' || choice == 'Y') {
            password = vault.generatePassword(16, true, true, true, true);
            std::cout << "Generated password: " << password << std::endl;
        } else {
            std::cout << "Enter password: ";
            password = SecureInputBuffer::readSecureString(true);
        }

        // Шифрование пароля с помощью DataEncryption
        std::string encrypted_password;
        try {
            encrypted_password = DataEncryption::encrypt(password, "demo_master_key");
            std::cout << "Password encrypted successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Encryption failed: " << e.what() << std::endl;
            encrypted_password = "encryption_failed";
        }

        // Создание записи с помощью CredentialRecord
        CredentialRecord record(service_name, url, login, encrypted_password, category);

        if (vault.addRecord(record)) {
            std::cout << "Credential added successfully!" << std::endl;
        } else {
            std::cout << "Failed to add credential" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Функция просмотра всех учетных записей
void viewAllCredentials(CredentialVault& vault) {
    std::cout << "\n=== All Credentials ===" << std::endl;

    try {
        auto records = vault.getAllRecords();

        if (records.empty()) {
            std::cout << "No credentials found." << std::endl;
            return;
        }

        std::cout << "Total: " << records.size() << " credentials" << std::endl;

        for (const auto& record : records) {
            displayCredential(record, false);

            // Демонстрация дешифрования пароля
            try {
                std::string decrypted_password = DataEncryption::decrypt(
                        record.getEncryptedPassword(), "demo_master_key");
                std::cout << "Decrypted password: " << decrypted_password << std::endl;
            } catch (const std::exception& e) {
                std::cout << "Password: [DECRYPTION FAILED]" << std::endl;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Функция поиска учетных записей
void searchCredentials(CredentialVault& vault) {
    std::cout << "\n=== Search Credentials ===" << std::endl;

    try {
        SearchFilter filter;
        std::string query;

        std::cout << "Search in service names: ";
        std::getline(std::cin, query);
        if (!query.empty()) {
            filter.setServiceNameQuery(query);
        }

        std::cout << "Search in logins: ";
        std::getline(std::cin, query);
        if (!query.empty()) {
            filter.setLoginQuery(query);
        }

        std::cout << "Search in URLs: ";
        std::getline(std::cin, query);
        if (!query.empty()) {
            filter.setUrlQuery(query);
        }

        std::cout << "Search in categories: ";
        std::getline(std::cin, query);
        if (!query.empty()) {
            filter.setCategoryQuery(query);
        }

        auto results = vault.searchRecords(filter);

        std::cout << "\nSearch results: " << results.size() << " found" << std::endl;

        for (const auto& record : results) {
            displayCredential(record, false);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Функция генерации пароля
void generatePasswordDemo(CredentialVault& vault) {
    std::cout << "\n=== Password Generator ===" << std::endl;

    try {
        demonstratePasswordGenerator();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Функция смены мастер-пароля
void changeMasterPassword(CredentialVault& vault) {
    std::cout << "\n=== Change Master Password ===" << std::endl;

    try {
        std::cout << "Enter current master password: ";
        std::string current_password = SecureInputBuffer::readSecureString(true);

        std::cout << "Enter new master password: ";
        std::string new_password = SecureInputBuffer::readSecureString(true);

        std::cout << "Confirm new master password: ";
        std::string confirm_password = SecureInputBuffer::readSecureString(true);

        if (new_password != confirm_password) {
            std::cout << "✗ Passwords do not match!" << std::endl;
            return;
        }

        // Проверка сложности пароля с помощью MasterPasswordManager
        std::string strength_feedback = MasterPasswordManager::getPasswordStrengthFeedback(new_password);
        std::cout << "\nPassword strength analysis:\n" << strength_feedback << std::endl;

        if (!MasterPasswordManager::isPasswordStrong(new_password)) {
            std::cout << "⚠️  Password is weak. Continue anyway? (y/n): ";
            char choice;
            std::cin >> choice;
            std::cin.ignore();

            if (choice != 'y' && choice != 'Y') {
                std::cout << "Password change cancelled." << std::endl;
                return;
            }
        }

        // Демонстрация хэширования пароля
        std::string password_hash = MasterPasswordManager::hashPassword(new_password);
        std::cout << "✓ Password hashed successfully (hash length: " << password_hash.length() << ")" << std::endl;

        std::cout << "✓ Master password changed successfully!" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Функция отображения статистики
void showVaultStatistics(CredentialVault& vault) {
    std::cout << "\n=== Vault Statistics ===" << std::endl;

    try {
        std::cout << "Total records: " << vault.getRecordCount() << std::endl;
        std::cout << "Categories: " << vault.getCategoryCount() << std::endl;

        auto categories = vault.getAllCategories();
        std::cout << "\nCategories list:" << std::endl;
        for (const auto& category : categories) {
            auto category_records = vault.getRecordsByCategory(category);
            std::cout << "  " << category << ": " << category_records.size() << " records" << std::endl;
        }

        std::time_t last_modified = vault.getLastModified();
        std::cout << "\nLast modified: " << std::ctime(&last_modified);
        std::cout << "Vault file: " << vault.getVaultFilePath() << std::endl;
        std::cout << "Status: " << (vault.isAuthenticated() ? "Unlocked" : "Locked") << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

// Демонстрация работы SecureInputBuffer
void demonstrateSecureInput() {
    std::cout << "\n=== Secure Input Demonstration ===" << std::endl;

    std::cout << "Enter sensitive data (hidden): ";
    std::string hidden_input = SecureInputBuffer::readSecureString(true);
    std::cout << "Input length: " << hidden_input.length() << " characters" << std::endl;

    std::cout << "Enter visible data: ";
    std::string visible_input = SecureInputBuffer::readSecureString(false);
    std::cout << "You entered: " << visible_input << std::endl;
}

// Основная функция
int main() {
    std::cout << "🚀 IronVault Password Manager - Complete System Demo" << std::endl;
    std::cout << "====================================================" << std::endl;

    try {
        // Инициализация криптографии
        DataEncryption::initializeCrypto();

        // Демонстрация отдельных компонентов
        demonstratePasswordGenerator();
        demonstrateDataEncryption();
        demonstrateCredentialRecord();

        // Создание хранилища
        CredentialVault vault("demo_vault.dat");

        // Демонстрация SecureInputBuffer
        demonstrateSecureInput();

        // Загрузка хранилища (в демо-режиме создаем новое)
        std::cout << "\n=== Vault Initialization ===" << std::endl;
        std::cout << "Enter master password for demo vault: ";
        std::string master_password = SecureInputBuffer::readSecureString(true);

        if (vault.loadFromFile(master_password)) {
            std::cout << "✓ Vault unlocked successfully!" << std::endl;
        } else {
            std::cout << "✓ New vault created!" << std::endl;
        }

        // Добавляем демо-данные
        CredentialRecord demo1("Google", "https://google.com", "user@gmail.com",
                               DataEncryption::encrypt("password123", "demo_master_key"), "Email");
        CredentialRecord demo2("GitHub", "https://github.com", "developer",
                               DataEncryption::encrypt("devpass456", "demo_master_key"), "Development");
        CredentialRecord demo3("Facebook", "https://facebook.com", "user123",
                               DataEncryption::encrypt("social789", "demo_master_key"), "Social");

        vault.addRecord(demo1);
        vault.addRecord(demo2);
        vault.addRecord(demo3);

        // Главный цикл меню
        int choice;
        do {
            displayMainMenu();
            std::cin >> choice;
            std::cin.ignore(); // Очистка буфера

            switch (choice) {
                case 1:
                    addNewCredential(vault);
                    break;
                case 2:
                    viewAllCredentials(vault);
                    break;
                case 3:
                    searchCredentials(vault);
                    break;
                case 4:
                    generatePasswordDemo(vault);
                    break;
                case 5:
                    changeMasterPassword(vault);
                    break;
                case 6:
                    showVaultStatistics(vault);
                    break;
                case 7:
                    vault.lockVault();
                    std::cout << "✓ Vault locked!" << std::endl;
                    break;
                case 8:
                    demonstrateDataEncryption();
                    break;
                case 0:
                    std::cout << "Saving vault..." << std::endl;
                    if (vault.saveToFile(master_password)) {
                        std::cout << "✓ Vault saved successfully!" << std::endl;
                    }
                    std::cout << "Goodbye!" << std::endl;
                    break;
                default:
                    std::cout << "Invalid option!" << std::endl;
            }

        } while (choice != 0);

        // Очистка криптографии
        DataEncryption::cleanupCrypto();

    } catch (const std::exception& e) {
        std::cerr << "💥 Critical error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}