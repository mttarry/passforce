#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

#define IV_LEN              16
#define KDF_ITERATIONS      10000
#define KEY_LEN             256 // 32 bytes
#define SALT_LEN            128
#define HEADER_SIZE         (SALT_LEN + IV_LEN)
#define MAX_PASSWORD_LEN    128
#define MAX_USERNAME_LEN    128
#define MAX_SITE_NAME_LEN   128

#define AES_256_BLK_SZ      16

#define CHARSET             "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

#define SUCCESS             1
#define FAIL                -1

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "[DEBUG] " fmt)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

typedef struct {
    unsigned char *bytes;
    size_t size;
} Buffer;

size_t get_file_size(FILE *fp);
int append_newline(FILE *fp);
int write_bytes(FILE *fp, const unsigned char *bytes, size_t num_bytes);
int write_file(FILE *fp, Buffer *buf, size_t offset, int whence);
int read_file(FILE *fp, Buffer *buf, size_t offset);
int str_check_len(const char *str, size_t len);

#endif