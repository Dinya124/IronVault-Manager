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

// Сеттеры для критериев поиска
void SearchFilter::setServiceNameQuery(const std::string &query) {
    service_name_query = query;
}

void SearchFilter::setLoginQuery(const std::string &query) {
    login_query = query;
}

void SearchFilter::setUrlQuery(const std::string &query) {
    url_query = query;
}

void SearchFilter::setCategoryQuery(const std::string &query) {
    category_query = query;
}

void SearchFilter::setNotesQuery(const std::string &query) {
    notes_query = query;
}

// Сеттеры для временного диапазона
void SearchFilter::setDateRange(std::time_t from, std::time_t to) {
    date_from = from;
    date_to = to;
}

void SearchFilter::setDateFrom(std::time_t from) {
    date_from = from;
}

void SearchFilter::setDateTo(std::time_t to) {
    date_to = to;
}

// Сеттеры для категорий
void SearchFilter::setCategories(const std::vector<std::string> &categories_list) {
    categories = categories_list;
}

void SearchFilter::setExcludedCategories(const std::vector<std::string> &excluded_list) {
    excluded_categories = excluded_list;
}

void SearchFilter::addCategory(const std::string &category) {
    if (!category.empty()) {
        categories.push_back(category);
    }
}

void SearchFilter::addExcludedCategory(const std::string &category) {
    if (!category.empty()) {
        excluded_categories.push_back(category);
    }
}

// Очистка критериев
void SearchFilter::clear() {
    service_name_query.clear();
    login_query.clear();
    url_query.clear();
    category_query.clear();
    notes_query.clear();
    case_sensitive = false;
    exact_match = false;
    search_in_notes = false;
    date_from = 0;
    date_to = 0;
    categories.clear();
    excluded_categories.clear();
}

void SearchFilter::clearServiceNameQuery() {
    service_name_query.clear();
}

void SearchFilter::clearLoginQuery() {
    login_query.clear();
}

void SearchFilter::clearUrlQuery() {
    url_query.clear();
}

void SearchFilter::clearCategoryQuery() {
    category_query.clear();
}

void SearchFilter::clearNotesQuery() {
    notes_query.clear();
}

void SearchFilter::clearDateRange() {
    date_from = 0;
    date_to = 0;
}

void SearchFilter::clearCategories() {
    categories.clear();
}

void SearchFilter::clearExcludedCategories() {
    excluded_categories.clear();
}

// Геттеры
std::string SearchFilter::getServiceNameQuery() const { return service_name_query; }

std::string SearchFilter::getLoginQuery() const { return login_query; }

std::string SearchFilter::getUrlQuery() const { return url_query; }

std::string SearchFilter::getCategoryQuery() const { return category_query; }

std::string SearchFilter::getNotesQuery() const { return notes_query; }

bool SearchFilter::isCaseSensitive() const { return case_sensitive; }

bool SearchFilter::isExactMatch() const { return exact_match; }

bool SearchFilter::isSearchInNotes() const { return search_in_notes; }

std::time_t SearchFilter::getDateFrom() const { return date_from; }

std::time_t SearchFilter::getDateTo() const { return date_to; }

std::vector<std::string> SearchFilter::getCategories() const { return categories; }

std::vector<std::string> SearchFilter::getExcludedCategories() const { return excluded_categories; }