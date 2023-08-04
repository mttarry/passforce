#ifndef CRYPTO_H
#define CRYPTO_H


#include "utils.h"
#include "database.h"

int encrypt(Buffer *inb, Buffer *outb, const char *master_password, const Header *header);
int decrypt(Buffer *inb, Buffer *outb, const char *master_password, const Header *header);
size_t get_nearest_blocksize(size_t in, size_t blocksize);
int init_random(unsigned char *bytes, size_t size);
int generate_password(char *password);

#endif