#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <iomanip>
#include <algorithm>

// Подключаем ваши заголовочные файлы
#include "CredentialVault.h"
#include "CredentialRecord.h"
#include "SecureInputBuffer.h"
#include "SearchFilter.h"
#include "PasswordGenerator.h"

// --- Вспомогательные функции ---

// Утилита для очистки потока ввода (чтобы getline не считывал пустую строку после cin)
void clearInputBuffer() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// Надежная пауза
void pauseConsole() {
    std::cout << "\nНажмите Enter, чтобы продолжить...";
    // Проверяем, если в буфере остался лишний '\n' от предыдущего ввода
    //if (std::cin.peek() == '\n'){ std::cin.ignore();}
    std::cin.get();
}

// Функция для вывода заголовка
void printHeader() {
    // Используем переводы строк вместо очистки экрана
    std::cout << "\n\n\n";
    std::cout << "========================================\n";
    std::cout << "      IRON VAULT PASSWORD MANAGER       \n";
    std::cout << "========================================\n";
}

// Функция для вывода одной записи (кратко)
void printRecordSummary(const CredentialRecord& record) {
    std::cout << "  Service: " << std::left << std::setw(20) << record.getServiceName()
              << " | Login: " << std::left << std::setw(20) << record.getLogin()
              << " | Category: " << record.getCategory() << "\n";
}

void viewRecordDetails(const CredentialRecord& record, const std::string& masterPassword) {
    std::cout << "\n--- Детали записи ---\n";
    std::cout << "Сервис:    " << record.getServiceName() << "\n";
    std::cout << "URL:       " << record.getUrl() << "\n";
    std::cout << "Логин:     " << record.getLogin() << "\n";
    std::cout << "Категория: " << record.getCategory() << "\n";

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

    // Очистка буфера после выбора пункта меню
    if (std::cin.peek() != '\n') {
        clearInputBuffer();
    } else {
        std::cin.ignore();
    }

    std::cout << "\n--- Новая запись ---\n";
    std::cout << "Сервис: ";
    std::getline(std::cin, service);

    if (service.empty()) {
        std::cout << "Имя сервиса не может быть пустым!\n";
        return;
    }
    if (!vault.isServiceNameUnique(service)) {
        std::cout << "Ошибка: Такой сервис уже существует!\n";
        return;
    }

    std::cout << "URL: "; std::getline(std::cin, url);
    std::cout << "Логин: "; std::getline(std::cin, login);
    std::cout << "Категория: "; std::getline(std::cin, category);

    std::cout << "Сгенерировать пароль? (y/n): ";
    char ch;
    if (!(std::cin >> ch)) {
        std::cin.clear(); clearInputBuffer();
        ch = 'n'; // При ошибке ввода по умолчанию не генерируем
    }
    clearInputBuffer();

    if (ch == 'y' || ch == 'Y') {
        password = vault.generatePassword(16, true, true, true, true);
        std::cout << "Сгенерирован пароль: " << password << "\n";
    } else {
        std::cout << "Введите пароль: ";
        password = SecureInputBuffer::readSecureString();
        std::cout << "\n";
    }

    try {
        std::string encPass = DataEncryption::encrypt(password, masterPassword);
        CredentialRecord rec(service, url, login, encPass, category);
        if (vault.addRecord(rec)) {
            std::cout << "Успешно добавлено!\n";
        } else {
            std::cout << "Не удалось добавить запись.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Ошибка: " << e.what() << "\n";
    }
}

void handleShowRecords(CredentialVault& vault, const std::string& masterPassword, const std::vector<CredentialRecord>& recordsToShow) {
    if (recordsToShow.empty()) {
        std::cout << "Нет записей для отображения.\n";
        return;
    }

    std::cout << "\n--- Найдено записей (" << recordsToShow.size() << ") ---\n";
    for (size_t i = 0; i < recordsToShow.size(); ++i) {
        std::cout << std::setw(2) << i + 1 << ". " << recordsToShow[i].getServiceName()
                  << " (" << recordsToShow[i].getLogin() << ")\n";
    }

    std::cout << "\nВведите номер для просмотра (0 - назад): ";
    int choice;
    if (!(std::cin >> choice)) {
        std::cin.clear(); clearInputBuffer(); return;
    }
    clearInputBuffer();

    if (choice > 0 && choice <= (int)recordsToShow.size()) {
        // Мы ищем запись по ее service_name, чтобы избежать проблем с копированием
        std::string sName = recordsToShow[choice-1].getServiceName();
        CredentialRecord* r = vault.findRecord(sName);
        if (r) {
            viewRecordDetails(*r, masterPassword);
        } else {
            std::cout << "Ошибка: Запись не найдена в хранилище.\n";
        }
    }
}

void handleSearch(CredentialVault& vault, const std::string& masterPassword) {
    std::string query;
    char ch;

    // Очистка буфера после выбора пункта меню
    if (std::cin.peek() != '\n') {
        clearInputBuffer();
    } else {
        std::cin.ignore();
    }

    std::cout << "\n--- Поиск записей ---\n";
    std::cout << "Искать по: 1) Имя сервиса, 2) Логин, 3) URL, 4) Категория: ";

    int typeChoice = 0;
    if (!(std::cin >> typeChoice)) {
        std::cin.clear(); clearInputBuffer();
        std::cout << "Неверный выбор.\n";
        return;
    }
    clearInputBuffer();

    std::cout << "Введите поисковый запрос: ";
    std::getline(std::cin, query);

    if (query.empty()) {
        std::cout << "Запрос не может быть пустым.\n";
        return;
    }

    SearchFilter filter;
    switch (typeChoice) {
        case 1: filter.setServiceNameQuery(query); break;
        case 2: filter.setLoginQuery(query); break;
        case 3: filter.setUrlQuery(query); break;
        case 4: filter.setCategoryQuery(query); break;
        default:
            std::cout << "Неверный тип поиска.\n";
            return;
    }

    // Проводим поиск
    std::vector<CredentialRecord> results = vault.searchRecords(filter);

    // Показываем результаты, используя общую функцию
    handleShowRecords(vault, masterPassword, results);
}

// --- Main ---

int main() {
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

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
            std::cout << "Вход выполнен! Загружено записей: " << vault.getAllRecords().size() << "\n";
            auth = true;
        } else {
            std::cout << "Ошибка входа. Повторить? (y/n): ";
            char c;
            if (!(std::cin >> c)) c = 'y'; // По умолчанию "да" при ошибке ввода
            clearInputBuffer();
            if (c == 'n' || c == 'N') return 0;
        }
    }

    bool running = true;
    while (running) {
        printHeader();
        std::cout << "1. Найти запись\n"; // <-- Ваш новый поиск
        std::cout << "2. Добавить запись\n";
        std::cout << "3. Показать все\n";
        std::cout << "4. Категории\n";
        std::cout << "5. Генератор\n";
        std::cout << "6. Сохранить и Выйти\n";
        std::cout << "0. Выйти без сохранения\n";
        std::cout << "Выбор: ";

        int choice;
        // ЗАЩИТА ОТ СБОЯ МЕНЮ
        if (!(std::cin >> choice)) {
            std::cin.clear(); // Сброс флага ошибки
            clearInputBuffer(); // Очистка буфера
            std::cout << "Пожалуйста, введите число.\n";
            pauseConsole(); // Добавляем паузу, чтобы пользователь увидел ошибку
            continue;
        }

        switch (choice) {
            case 1:
                handleSearch(vault, masterPassword);
                pauseConsole();
                break;
            case 2:
                handleAddRecord(vault, masterPassword);
                pauseConsole();
                break;
            case 3:
                handleShowRecords(vault, masterPassword, vault.getAllRecords());
                pauseConsole();
                break;
            case 4: {
                auto cats = vault.getAllCategories();
                std::cout << "\n--- Категории ---\n";
                for (const auto& c : cats) std::cout << "- " << c << "\n";
                pauseConsole();
                break;
            }
            case 5:
                std::cout << "\nСгенерированный пароль: "
                          << vault.generatePassword(16, true, true, true, true) << "\n";
                pauseConsole();
                break;
            case 6:
                if (vault.saveToFile(masterPassword)) std::cout << "Хранилище сохранено.\n";
                else std::cout << "ОШИБКА СОХРАНЕНИЯ!\n";
                running = false;
                break;
            case 0:
                std::cout << "Выход без сохранения...\n";
                running = false;
                break;
            default:
                std::cout << "Неверный выбор.\n";
                pauseConsole();
                break;
        }
    }
    return 0;
}