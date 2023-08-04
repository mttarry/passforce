#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "commands.h"
#include "utils.h"


int initialize_database(FILE *db, const char *master_password) {
    Header header = { 0 };

    if (append_header(db, &header) != SUCCESS) {
        DEBUG_PRINT("Error appending header to database\n");
        return FAIL;
    }

    return SUCCESS;
}

int add_new_credentials(FILE *db, const char *master_password, Entry *entry, bool generate) {
    if (find_entry(db, entry) == FAIL) {
        if (handle_add_new_credentials(db, entry, generate) != SUCCESS) {
            DEBUG_PRINT("Error in add_new_credentials(): appending new credentials to database\n");
            return FAIL;
        }
    }
    else {
        printf("Credentials already entered for %s\n", entry->site_name);
    }

    return SUCCESS;
}

int retrieve_credentials(FILE *db, const char *master_password, Entry *entry) {
    if (handle_retrieve_credentials(db, entry) != SUCCESS) {
        printf("No credentials exists for %s\n", entry->site_name);
        return FAIL;
    }
    else {
        printf("Username: %s\nPassword: %s\n", entry->username, entry->password);
    }

    return SUCCESS;
}

int print_all_credentials(FILE *db, const char *master_password) {
    char line[256] = { 0 };
    char *url = NULL, *username = NULL, *password = NULL;

    fseek(db, HEADER_SIZE, SEEK_SET);

    while (fgets(line, sizeof(line), db) != NULL) {
        url = strtok(line, ":");
        username = strtok(NULL, ":");
        password = strtok(NULL, "\n");

        printf("%s\n  Username: %s\n  Password %s\n", url, username, password);
    }

    return SUCCESS;
}

int delete_credentials(FILE *db, const char *master_password, Entry *entry) {
    if (find_entry(db, entry) == FAIL) {
        printf("Credentials do not exist for %s\n", entry->site_name);        
    }
    else if (handle_delete_credentials(db, entry) != SUCCESS) {
        DEBUG_PRINT("Error in delete_credentials(): error removing credentials from database");
        return FAIL;
    }

    return SUCCESS;
}


int update_credentials(FILE *db, const char *master_password, Entry *entry, bool generate) {
    if (find_entry(db, entry) == FAIL) {
        printf("Credentials do not exist for %s\n", entry->site_name);        
    }
    else {
        if (handle_delete_credentials(db, entry) != SUCCESS) {
            DEBUG_PRINT("Error in update_credentials(): error removing credentials from database\n");
            return FAIL;
        }
        if (handle_add_new_credentials(db, entry, generate) != SUCCESS) {
            DEBUG_PRINT("Error in update_credentials(): appending new credentials to database\n");
            return FAIL;
        }
    }

    return SUCCESS;
}