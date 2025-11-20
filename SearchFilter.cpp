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

