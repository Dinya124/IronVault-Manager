#ifndef DATAENCRYPTION_H
#define DATAENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

class DataEncryption{
private:
    static const size_t KEY_LENGTH = 32;
    static const size_t IV_LENGTH = 16;
    static const size_t SALT_LENGTH = 16;
    static const int ITERATIONS = 100000;

};

#endif