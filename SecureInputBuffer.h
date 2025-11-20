#ifndef IRONVAULT_MANAGER_SECUREINPUTBUFFER_H
#define IRONVAULT_MANAGER_SECUREINPUTBUFFER_H

#include <vector>
#include <string>
#include <functional>

class SecureInputBuffer {

private:
    std::vector<char> buffer;
    size_t position;
    bool echo_enabled;
    char mask_char;

    // Константы
    static const size_t DEFAULT_BUFFER_SIZE = 1024;
    static const size_t MAX_BUFFER_SIZE = 65536;
    static const char BACKSPACE = 127;
    static const char ENTER = 10;
    static const char CTRL_C = 3;
    static const char CTRL_D = 4;
};


#endif //IRONVAULT_MANAGER_SECUREINPUTBUFFER_H
