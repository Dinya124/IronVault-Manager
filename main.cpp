#include <string>
#include <vector>
#include <limits>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <stdexcept>

// Подключение модулей проекта
#include "CredentialVault.h"
#include "CredentialRecord.h"
#include "BankCardRecord.h"     // Новый класс (из предыдущих шагов)
#include "SecureInputBuffer.h"
#include "SearchFilter.h"
#include "PasswordGenerator.h"
#include "SecureRepository.h"   // Шаблонный класс
#include "VaultStatistics.h"    // Шаблонная функция
#include "CompileTimeFeatures.h" // !!! НОВЫЙ МОДУЛЬ (C++20) !!!

// --- Вспомогательные функции ---

void clearInputBuffer() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void pauseConsole() {
    std::cout << "\nНажмите Enter, чтобы продолжить...";
    if (std::cin.peek() == '\n') std::cin.ignore();
    std::cin.get();
}

// --- ДЕМОНСТРАЦИИ ЗАДАНИЙ ---

// Задание 1: STL и Шаблоны
void demonstrateSTLFeatures() {
    std::cout << "\n=== DEMONSTRATION OF C++ FEATURES (STL & Templates) ===\n";

    // 1. Использование шаблонного класса SecureRepository с ограничением типа
    std::cout << "[1] Template Class (SecureRepository<T>):\n";
    SecureRepository<CredentialRecord> demoRepo;

    CredentialRecord rec1("DemoService", "http://demo.com", "user1", "pass123", "Work");
    rec1.setDescription("DemoService");

    CredentialRecord rec2("TestApp", "http://test.app", "admin", "admin", "Personal");
    rec2.setDescription("TestApp");

    demoRepo.add(rec1);
    demoRepo.add(rec2);

    std::cout << "    Records in template repo: " << demoRepo.count() << "\n";

    // 2. Использование шаблонной функции с ограничением типа (SFINAE)
    std::cout << "[2] Template Function (VaultStats::calculateAverage):\n";
    std::vector<double> entropies = {55.5, 80.0, 120.5, 40.0};
    double avg = VaultStats::calculateAverage(entropies);
    std::cout << "    Calculated Average Entropy: " << avg << " bits\n";

    // 3. Использование STL Алгоритмов (find_if)
    std::cout << "[3] STL Algorithm (std::find_if):\n";
    auto& storage = demoRepo.getStorage();
    auto it = std::find_if(storage.begin(), storage.end(), [](const std::shared_ptr<CredentialRecord>& r){
        return r->getCategory() == "Personal";
    });

    if (it != storage.end()) {
        std::cout << "    Found Personal account: " << (*it)->getServiceName() << "\n";
    }

    std::cout << "=======================================================\n";
}

// Задание 2: C++20 (consteval, constinit)
void demonstrateCompileTimeFeatures() {
    std::cout << "\n=== DEMONSTRATION OF C++20 FEATURES ===\n";

    // 1. consteval: Хеширование строки во время компиляции
    // В бинарном файле строки "IRONVAULT" не будет, будет только число.
    constexpr uint64_t expectedHash = compileTimeHash("IRONVAULT");
    std::cout << "[1] consteval Hash of 'IRONVAULT': " << expectedHash << "\n";

    // 2. constinit: Гарантированная статическая инициализация
    // Объект globalCryptoConfig инициализирован до main()
    std::cout << "[2] constinit Configuration:\n";
    std::cout << "    AES Key Size: " << globalCryptoConfig.aes_key_size << " bits (calculated at compile-time)\n";
    std::cout << "    Optimal Buffer: " << globalCryptoConfig.getOptimalBufferSize() << " bytes\n";
    std::cout << "    Safety Margin: " << globalCryptoConfig.buffer_safety_margin << "\n";

    std::cout << "=======================================\n\n";
}

// --- Интерфейс ---

void printHeader() {
    std::cout << "\n\n\n";
    std::cout << "========================================\n";
    std::cout << "      IRON VAULT PASSWORD MANAGER       \n";
    std::cout << "========================================\n";
    std::cout << "Сессия: Создано объектов: " << CredentialRecord::getRecordsCreatedCount() << "\n";
    std::cout << "========================================\n";
}

void printRecordSummary(const CredentialRecord& record) {
    std::cout << record << "\n"; // Перегруженный оператор <<
}

void viewRecordDetails(const CredentialRecord& record, const std::string& masterPassword) {
    std::cout << "\n--- Детали записи ---\n";
    std::cout << "Сервис:    " << record.getServiceName() << "\n";
    std::cout << "URL:       " << record.getUrl() << "\n";
    std::cout << "Логин:     " << record.getLogin() << "\n";
    std::cout << "Категория: " << record.getCategory() << "\n";
    std::cout << "Дата изм.: " << record.getLastModified() << "\n";

    std::cout << "Пароль:    ";
    try {
        std::string decrypted = record.getPassword(masterPassword);
        std::cout << decrypted << "\n";
    } catch (...) {
        std::cout << "[ОШИБКА РАСШИФРОВКИ]\n";
    }
    std::cout << "---------------------\n";
}

// --- Обработка команд ---

void handleAddRecord(CredentialVault& vault, const std::string& masterPassword) {
    std::string service, login, url, category, password;

    if (std::cin.peek() != '\n') clearInputBuffer();
    else std::cin.ignore();

    std::cout << "\n--- Новая запись ---\n";

    try {
        std::cout << "Сервис: "; std::getline(std::cin, service);

        if (!vault.isServiceNameUnique(service)) {
            throw std::runtime_error("Service name already exists");
        }

        std::cout << "URL: "; std::getline(std::cin, url);
        std::cout << "Логин: "; std::getline(std::cin, login);
        std::cout << "Категория: "; std::getline(std::cin, category);

        std::cout << "Сгенерировать пароль? (y/n): ";
        char ch;
        if (!(std::cin >> ch)) { std::cin.clear(); clearInputBuffer(); ch = 'n'; }
        clearInputBuffer();

        if (ch == 'y' || ch == 'Y') {
            password = vault.generatePassword(16, true, true, true, true);
            std::cout << "Сгенерирован пароль: " << password << "\n";
        } else {
            std::cout << "Введите пароль: ";
            password = SecureInputBuffer::readSecureString();
            std::cout << "\n";
        }

        std::string encPass = DataEncryption::encrypt(password, masterPassword);
        CredentialRecord rec(service, url, login, encPass, category);

        if (vault.addRecord(rec)) {
            std::cout << "Успешно добавлено!\n";
        } else {
            std::cout << "Не удалось добавить запись.\n";
        }

    } catch (const std::exception& e) {
        std::cout << "\n[ОШИБКА]: " << e.what() << "\n";
    }
}

void handleShowRecords(CredentialVault& vault, const std::string& masterPassword, const std::vector<CredentialRecord>& recordsToShow) {
    if (recordsToShow.empty()) {
        std::cout << "Нет записей для отображения.\n";
        return;
    }

    std::cout << "\n--- Найдено записей (" << recordsToShow.size() << ") ---\n";
    for (size_t i = 0; i < recordsToShow.size(); ++i) {
        std::cout << std::setw(2) << i + 1 << ". ";
        printRecordSummary(recordsToShow[i]);
    }

    std::cout << "\nВведите номер для просмотра (0 - назад): ";
    int choice;
    if (!(std::cin >> choice)) { std::cin.clear(); clearInputBuffer(); return; }
    clearInputBuffer();

    if (choice > 0 && choice <= (int)recordsToShow.size()) {
        std::string sName = recordsToShow[choice-1].getServiceName();
        CredentialRecord* r = vault.findRecord(sName);
        if (r) viewRecordDetails(*r, masterPassword);
        else std::cout << "Ошибка: Запись не найдена.\n";
    }
}

void handleSearch(CredentialVault& vault, const std::string& masterPassword) {
    std::string query;
    if (std::cin.peek() != '\n') clearInputBuffer(); else std::cin.ignore();

    std::cout << "\n--- Поиск записей ---\n";
    std::cout << "Введите поисковый запрос: ";
    std::getline(std::cin, query);
    if (query.empty()) return;

    SearchFilter f1; f1.setServiceNameQuery(query);
    SearchFilter f2; f2.setLoginQuery(query);

    // Объединяем фильтры (Operator overloading demo)
    SearchFilter finalFilter = f1 + f2;

    std::vector<CredentialRecord> results = vault.searchRecords(finalFilter);
    handleShowRecords(vault, masterPassword, results);
}

void handleStatistics(CredentialVault& vault) {
    std::cout << "\n--- Статистика хранилища (STL) ---\n";
    std::cout << "Всего записей: " << vault.getRecordCount() << "\n";
    std::cout << "Всего категорий: " << vault.getCategoryCount() << "\n";
    double avg = vault.calculateAverageEncryptionStrength();
    std::cout << "Средняя сложность шифрования (metric): " << avg << "\n";

    pauseConsole();
}

// --- MAIN ---

int main() {
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    // 1. Демонстрация STL (из предыдущего задания)
    demonstrateSTLFeatures();

    // 2. Демонстрация C++20 (НОВОЕ ЗАДАНИЕ)
    demonstrateCompileTimeFeatures();

    pauseConsole();

    // Инициализация хранилища
    CredentialVault vault("ironvault.dat");
    std::string masterPassword;
    bool auth = false;

    printHeader();

    while (!auth) {
        std::cout << "Введите Мастер-пароль: ";
        masterPassword = SecureInputBuffer::readSecureString();
        std::cout << "\n";

        if (masterPassword.empty()) {
            std::cout << "Пароль не может быть пустым.\n";
            continue;
        }

        if (vault.loadFromFile(masterPassword)) {
            std::cout << "Вход выполнен!\n";
            auth = true;
        } else {
            std::cout << "Ошибка входа. Повторить? (y/n): ";
            char c;
            if (!(std::cin >> c)) c = 'y';
            clearInputBuffer();
            if (c == 'n' || c == 'N') return 0;
        }
    }

    bool running = true;
    while (running) {
        printHeader();
        std::cout << "1. Найти запись\n";
        std::cout << "2. Добавить запись\n";
        std::cout << "3. Показать все\n";
        std::cout << "4. Категории\n";
        std::cout << "5. Генератор паролей\n";
        std::cout << "6. Статистика (STL Demo)\n";
        std::cout << "7. Сохранить и Выйти\n";
        std::cout << "0. Выйти без сохранения\n";
        std::cout << "Выбор: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear(); clearInputBuffer();
            continue;
        }

        switch (choice) {
            case 1: handleSearch(vault, masterPassword); pauseConsole(); break;
            case 2: handleAddRecord(vault, masterPassword); pauseConsole(); break;
            case 3: handleShowRecords(vault, masterPassword, vault.getAllRecords()); pauseConsole(); break;
            case 4: {
                auto cats = vault.getAllCategories();
                std::cout << "\n--- Категории ---\n";
                for (const auto& c : cats) std::cout << "- " << c << "\n";
                pauseConsole();
                break;
            }
            case 5:
                std::cout << "\nПароль: " << vault.generatePassword(16, true, true, true, true) << "\n";
                pauseConsole();
                break;
            case 6: handleStatistics(vault); break;
            case 7:
                if (vault.saveToFile(masterPassword)) std::cout << "Сохранено.\n";
                else std::cout << "ОШИБКА!\n";
                running = false;
                break;
            case 0: running = false; break;
            default: std::cout << "Неверный выбор.\n"; pauseConsole(); break;
        }
    }
    return 0;
}