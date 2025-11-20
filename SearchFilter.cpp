#include "SearchFilter.h"
#include <algorithm>
#include <cctype>
#include <ctime>

// Конструктор по умолчанию
SearchFilter::SearchFilter()
        : service_name_query(""),
          login_query(""),
          url_query(""),
          category_query(""),
          notes_query(""),
          case_sensitive(false),
          exact_match(false),
          search_in_notes(false),
          date_from(0),
          date_to(0) {
}

// Основной метод проверки соответствия записи критериям
bool SearchFilter::matches(const CredentialRecord &record) const {
    // Если фильтр не активен, все записи подходят
    if (!isActive()) {
        return true;
    }

    // Проверяем все критерии
    if (!matchesServiceName(record)) return false;
    if (!matchesLogin(record)) return false;
    if (!matchesUrl(record)) return false;
    if (!matchesCategory(record)) return false;
    if (!matchesNotes(record)) return false;
    if (!matchesDateRange(record)) return false;
    if (!matchesCategories(record)) return false;

    return true;
}

// Проверка соответствия имени сервиса
bool SearchFilter::matchesServiceName(const CredentialRecord &record) const {
    if (service_name_query.empty()) {
        return true;
    }

    std::string service_name = record.getServiceName();
    return matchesText(service_name, service_name_query);
}

// Проверка соответствия логина
bool SearchFilter::matchesLogin(const CredentialRecord &record) const {
    if (login_query.empty()) {
        return true;
    }

    std::string login = record.getLogin();
    return matchesText(login, login_query);
}

// Проверка соответствия URL
bool SearchFilter::matchesUrl(const CredentialRecord &record) const {
    if (url_query.empty()) {
        return true;
    }

    std::string url = record.getUrl();
    return matchesText(url, url_query);
}

// Проверка соответствия категории
bool SearchFilter::matchesCategory(const CredentialRecord &record) const {
    if (category_query.empty()) {
        return true;
    }

    std::string category = record.getCategory();
    return matchesText(category, category_query);
}

// Проверка соответствия заметок
bool SearchFilter::matchesNotes(const CredentialRecord &record) const {
    if (notes_query.empty() || !search_in_notes) {
        return true;
    }

    std::string notes = record.getNotes();
    return matchesText(notes, notes_query);
}

// Проверка соответствия временному диапазону
bool SearchFilter::matchesDateRange(const CredentialRecord &record) const {
    if (date_from == 0 && date_to == 0) {
        return true;
    }

    std::time_t record_time = record.getLastModified();

    if (date_from > 0 && record_time < date_from) {
        return false;
    }

    if (date_to > 0 && record_time > date_to) {
        return false;
    }

    return true;
}

// Проверка соответствия списку категорий
bool SearchFilter::matchesCategories(const CredentialRecord &record) const {
    std::string category = record.getCategory();

    // Проверка включенных категорий
    if (!categories.empty() && !isInCategories(category)) {
        return false;
    }

    // Проверка исключенных категорий
    if (!excluded_categories.empty() && isExcludedCategory(category)) {
        return false;
    }

    return true;
}
