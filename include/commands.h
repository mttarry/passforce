#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>
#include "database.h"

enum Commands {
    INIT_DB = 1,
    ADD_CREDS,
    RETRIEVE_CREDS,
    PRINT_ALL_CREDS,
    DELELTE_CREDS,
    UPDATE_CREDS
};

enum Param {
    MASTER_PASSWORD,
    SITE_NAME,
    PASSWORD,
    USERNAME
};

int initialize_database(FILE *db, const char *master_password);
int add_new_credentials(FILE *db, const char *master_password, Entry *entry, bool generate);
int retrieve_credentials(FILE *db, const char *master_password, Entry *entry);
int delete_credentials(FILE *db, const char *master_password, Entry *entry);
int update_credentials(FILE *db, const char *master_password, Entry *entry, bool generate);
int print_all_credentials(FILE *db, const char *master_password);

#endif