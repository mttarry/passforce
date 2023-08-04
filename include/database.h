#ifndef DATABASE_H
#define DATABASE_H

#include <stdbool.h>
#include <sys/types.h>
#include "utils.h"

typedef struct {
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
} Header;

typedef struct {
    char *site_name;
    char *username;
    char *password;
} Entry;

int read_header(FILE *fp, Header *header);
int append_header(FILE *db, Header *header);
int write_encrypted_database(FILE *db, const char *master_password);
int write_decrypted_database(FILE *db, const char *master_password);
ssize_t find_entry(FILE *db, Entry *entry);
int handle_retrieve_credentials(FILE *db, Entry *entry);
int handle_delete_credentials(FILE *db, Entry *entry);
int handle_add_new_credentials(FILE *db, Entry *entry, bool generate);

#endif

