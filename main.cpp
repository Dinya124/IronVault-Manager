#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <iomanip>

// Подключаем ваши заголовочные файлы
#include "CredentialVault.h"
#include "CredentialRecord.h"
#include "SecureInputBuffer.h"
#include "SearchFilter.h"
#include "PasswordGenerator.h"

// Утилита для очистки потока ввода (чтобы getline не считывал пустую строку после cin)
void clearInputBuffer() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// Утилита для паузы
void pauseConsole() {
    std::cout << "\nНажмите Enter, чтобы продолжить...";
    std::cin.get();
}

// Функция для вывода заголовка
void printHeader() {
    // Очистка экрана (системно-зависимая, для простоты просто отступы)
    std::cout << "\n\n========================================\n";
    std::cout << "      IRON VAULT PASSWORD MANAGER       \n";
    std::cout << "========================================\n";
}

// Функция для вывода одной записи (без пароля)
void printRecordSummary(const CredentialRecord& record) {
    std::cout << "Service: " << std::left << std::setw(20) << record.getServiceName()
              << " | Login: " << std::left << std::setw(20) << record.getLogin()
              << " | Category: " << record.getCategory() << "\n";
}

// Функция просмотра деталей записи (с расшифровкой)
void viewRecordDetails(const CredentialRecord& record, const std::string& masterPassword) {
    std::cout << "\n--- Детали записи ---\n";
    std::cout << "Сервис:    " << record.getServiceName() << "\n";
    std::cout << "URL:       " << record.getUrl() << "\n";
    std::cout << "Логин:     " << record.getLogin() << "\n";
    std::cout << "Категория: " << record.getCategory() << "\n";

    std::cout << "Пароль:    ";
    try {
        // Здесь используем мастер-пароль для расшифровки конкретной записи
        std::string decrypted = record.getPassword(masterPassword);
        std::cout << decrypted << "\n";
    } catch (const std::exception& e) {
        std::cout << "[ОШИБКА РАСШИФРОВКИ]\n";
    }

    // Форматирование времени
    std::time_t t = record.getLastModified();
    std::cout << "Изменено:  " << std::ctime(&t);
    std::cout << "---------------------\n";
}

// Меню добавления записи
void handleAddRecord(CredentialVault& vault, const std::string& masterPassword) {
    std::string service, login, url, category, password;

    std::cout << "\n--- Добавление новой записи ---\n";

    std::cout << "Введите название сервиса: ";
    std::getline(std::cin, service);

    std::cout << "Введите URL (необязательно): ";
    std::getline(std::cin, url);

    std::cout << "Введите логин: ";
    std::getline(std::cin, login);

    std::cout << "Введите категорию (Enter для 'General'): ";
    std::getline(std::cin, category);

    std::cout << "Сгенерировать пароль? (y/n): ";
    char choice;
    std::cin >> choice;
    clearInputBuffer();

    if (choice == 'y' || choice == 'Y') {
        // Используем встроенный генератор
        password = vault.generatePassword(16, true, true, true, true);
        std::cout << "Сгенерированный пароль: " << password << "\n";
    } else {
        std::cout << "Введите пароль: ";
        // Используем SecureInputBuffer для скрытия ввода пароля при создании
        password = SecureInputBuffer::readSecureString();
        std::cout << "\n";
    }

    // Шифруем пароль перед созданием объекта (CredentialRecord хранит уже зашифрованный)
    // ВАЖНО: Согласно вашей логике, CredentialRecord принимает уже зашифрованный пароль в конструкторе?
    // Проверим CredentialRecord.cpp. Конструктор принимает encrypted_password.
    // Значит, нам нужно зашифровать его здесь.

    try {
        // Шифруем сырой пароль, используя мастер-пароль
        std::string encryptedPass = DataEncryption::encrypt(password, masterPassword);

        CredentialRecord newRecord(service, url, login, encryptedPass, category);

        if (vault.addRecord(newRecord)) {
            std::cout << "Запись успешно добавлена!\n";
        } else {
            std::cout << "Ошибка добавления записи (возможно, имя сервиса занято).\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Ошибка: " << e.what() << "\n";
    }
}

// Меню поиска
void handleSearch(CredentialVault& vault, const std::string& masterPassword) {
    std::cout << "\nВведите поисковый запрос (сервис, логин или категория): ";
    std::string query;
    std::getline(std::cin, query);

    // Используем ваш SearchFilter
    SearchFilter filter = SearchFilter::createTextSearchFilter(query);

    std::vector<CredentialRecord> results = vault.searchRecords(filter);

    if (results.empty()) {
        std::cout << "Ничего не найдено.\n";
        return;
    }

    std::cout << "\nНайдено записей: " << results.size() << "\n";
    for (size_t i = 0; i < results.size(); ++i) {
        std::cout << i + 1 << ". ";
        printRecordSummary(results[i]);
    }

    std::cout << "\nВведите номер записи для просмотра пароля (0 для отмены): ";
    int choice;
    if (!(std::cin >> choice)) {
        std::cin.clear();
        clearInputBuffer();
        return;
    }
    clearInputBuffer();

    if (choice > 0 && choice <= static_cast<int>(results.size())) {
        // Получаем оригинальную запись из хранилища по имени сервиса,
        // чтобы убедиться, что работаем с актуальными данными
        std::string serviceName = results[choice - 1].getServiceName();
        CredentialRecord* record = vault.findRecord(serviceName);
        if (record) {
            viewRecordDetails(*record, masterPassword);
        }
    }
}

int main() {
    // Включаем поддержку кириллицы в консоли (если Windows)
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    std::string vaultFile = "ironvault.dat";
    CredentialVault vault(vaultFile);
    std::string masterPassword;
    bool isAuthenticated = false;

    printHeader();
    std::cout << "Добро пожаловать в IronVault.\n";

    // Цикл аутентификации
    while (!isAuthenticated) {
        std::cout << "\nПожалуйста, введите Мастер-пароль для входа или создания хранилища:\n";
        std::cout << "Пароль: ";

        // Используем ваш класс для скрытого ввода
        masterPassword = SecureInputBuffer::readSecureString();
        std::cout << "\n";

        if (masterPassword.empty()) {
            std::cout << "Пароль не может быть пустым.\n";
            continue;
        }

        std::cout << "Попытка открытия хранилища...\n";
        if (vault.loadFromFile(masterPassword)) {
            std::cout << "Успешный вход!\n";
            isAuthenticated = true;
        } else {
            std::cout << "Ошибка входа. Неверный пароль или файл поврежден.\n";
            std::cout << "Попробовать снова? (y/n): ";
            char retry;
            std::cin >> retry;
            clearInputBuffer();
            if (retry == 'n' || retry == 'N') return 0;
        }
    }

    // Основной цикл программы
    bool running = true;
    while (running) {
        printHeader();
        std::cout << "1. Найти запись\n";
        std::cout << "2. Добавить новую запись\n";
        std::cout << "3. Показать все записи\n";
        std::cout << "4. Показать все категории\n";
        std::cout << "5. Генератор паролей\n";
        std::cout << "6. Сохранить и Выйти\n";
        std::cout << "0. Выйти без сохранения\n";
        std::cout << "\nВаш выбор: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            clearInputBuffer();
            continue;
        }
        clearInputBuffer();

        switch (choice) {
            case 1:
                handleSearch(vault, masterPassword);
                pauseConsole();
                break;
            case 2:
                handleAddRecord(vault, masterPassword);
                // Автосохранение после добавления для безопасности
                vault.saveToFile(masterPassword);
                pauseConsole();
                break;
            case 3: {
                std::vector<CredentialRecord> all = vault.getAllRecords();
                if (all.empty()) {
                    std::cout << "Хранилище пусто.\n";
                } else {
                    std::cout << "\n--- Все записи ---\n";
                    for (const auto& rec : all) {
                        printRecordSummary(rec);
                    }
                }
                pauseConsole();
                break;
            }
            case 4: {
                std::vector<std::string> cats = vault.getAllCategories();
                std::cout << "\n--- Категории ---\n";
                for (const auto& cat : cats) std::cout << "- " << cat << "\n";
                pauseConsole();
                break;
            }
            case 5: {
                std::cout << "\nСгенерированный пароль: "
                          << vault.generatePassword(16, true, true, true, true) << "\n";
                pauseConsole();
                break;
            }
            case 6:
                if (vault.saveToFile(masterPassword)) {
                    std::cout << "Хранилище успешно сохранено. До свидания!\n";
                } else {
                    std::cout << "Ошибка при сохранении файла!\n";
                }
                running = false;
                break;
            case 0:
                std::cout << "Выход без сохранения...\n";
                running = false;
                break;
            default:
                std::cout << "Неверный выбор.\n";
                break;
        }
    }

    return 0;
}