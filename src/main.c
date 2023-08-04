#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "database.h"
#include "commands.h"
#include "utils.h"


void usage_error() {
    const char *usage = 
        "Usage: ./passforce [-m master_password] OPTIONS...\n"
        "PassForce is a secure credentials management application\n"
        "Master password is mandatory for all interactions with the database\n"
        "  -a\t\t print all credentials\n"
        "  -p\t\t password, for adding new credentials\n"
        "  -s\t\t site_name, for retrieving and adding/updating credentials\n"
        "  -n\t\t username, for adding/updating new credentials\n"
        "  -g\t\t generate, for generating random password\n"
        "  -u\t\t update, for updating credentials\n"
        "  -d\t\t delete, for deleting credentials associated with site_name\n";

    printf("%s\n", usage);
    exit(EXIT_FAILURE);
}

void check_usage(int flag, const char *master_password, Entry *entry, bool generate) {
    if (master_password == NULL) {
        usage_error();
    }

    switch (flag) {
        case INIT_DB:
            break;
        case PRINT_ALL_CREDS:
            break;
        case ADD_CREDS:
        case UPDATE_CREDS:
            if (entry->site_name == NULL || entry->username == NULL) {
                usage_error();
            }
            if ((entry->password != NULL && generate) || (entry->password == NULL && !generate)) {
                usage_error();
            }
            break;
        case RETRIEVE_CREDS:
        case DELELTE_CREDS:
            if (entry->site_name == NULL) {
                usage_error();
            }
            break;
        default:
            usage_error();
            break;
    }
}

void param_length_check(enum Param param, const char *str) {
    switch (param) {
        case MASTER_PASSWORD:
        case PASSWORD:
            if (!str_check_len(str, MAX_PASSWORD_LEN)) {
                printf("Maximum length of password is %lu\n", (size_t)MAX_PASSWORD_LEN);
                exit(EXIT_FAILURE);
            }
            break;
        case SITE_NAME:
            if (!str_check_len(str, MAX_SITE_NAME_LEN)) {
                printf("Maximum length of site_name is %lu\n", (size_t)MAX_SITE_NAME_LEN);
                exit(EXIT_FAILURE);
            }
            break;
        case USERNAME:
            if (!str_check_len(str, MAX_USERNAME_LEN)) {
                printf("Maximum length of username is %lu\n", (size_t)MAX_USERNAME_LEN);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            exit(EXIT_FAILURE);
            break;
    }
}


int main(int argc, char **argv) {
    FILE *db = NULL;
    char *file_mode = NULL, *master_password = NULL;
    bool generate = false;
    int opt = 0, flag = 0;
    Entry entry = { 0 };

    while ((opt = getopt(argc, argv, "m:ip::s:radugn:")) != -1) {
        switch (opt) {
        case 'm':
            master_password = optarg;
            param_length_check(MASTER_PASSWORD, master_password);
            break;
        case 'i':            
            flag = INIT_DB;
            break;
        case 'n':
            param_length_check(USERNAME, optarg);
            entry.username = optarg;
            break;
        case 'p':
            param_length_check(PASSWORD, optarg);
            entry.password = optarg;
            flag = ADD_CREDS;
            break;
        case 's':
            param_length_check(SITE_NAME, optarg);
            entry.site_name = optarg;
            break;
        case 'r':
            flag = RETRIEVE_CREDS;
            break;
        case 'a':
            flag = PRINT_ALL_CREDS;
            break;
        case 'd':
            flag = DELELTE_CREDS;
            break;
        case 'u':
            flag = UPDATE_CREDS;
            break;
        case 'g':
            generate = true;
            break;
        default: 
            usage_error();
        }
    }

    check_usage(flag, master_password, &entry, generate);
    
    // Create or open database for reading/writing
    file_mode = (flag == INIT_DB) ? "w+" : "r+";
    db = fopen("passwords.pf", file_mode);
    if (!db) {
        perror("Error opening database");
        exit(EXIT_FAILURE);
    }

    if (flag == INIT_DB) {
        initialize_database(db, master_password);
    }
    else {
        write_decrypted_database(db, master_password);
        
        switch (flag) {
            case ADD_CREDS:
                add_new_credentials(db, master_password, &entry, generate);
                break;
            case RETRIEVE_CREDS:
                entry.password = (char *)calloc(MAX_PASSWORD_LEN + 1, sizeof(char));
                entry.username = (char *)calloc(MAX_USERNAME_LEN + 1, sizeof(char));

                retrieve_credentials(db, master_password, &entry);
                
                free(entry.password);
                free(entry.username);
                break;
            case PRINT_ALL_CREDS:
                print_all_credentials(db, master_password);
                break;
            case DELELTE_CREDS:
                delete_credentials(db, master_password, &entry);
                break;
            case UPDATE_CREDS:
                update_credentials(db, master_password, &entry, generate);
                break;
            default:
                write_encrypted_database(db, master_password);
                usage_error();
                break;
        }
        
        write_encrypted_database(db, master_password);
    }


    fclose(db);

    exit(EXIT_SUCCESS);
}

