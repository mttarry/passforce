#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "database.h"
#include "crypto.h"


int read_header(FILE *fp, Header *header) {
    Buffer salt = { header->salt, SALT_LEN };
    Buffer iv = { header->iv, IV_LEN };

    if (read_file(fp, &salt, 0L) != SUCCESS) {
        DEBUG_PRINT("Error reading salt from header\n");
        return FAIL;
    }

    if (read_file(fp, &iv, SALT_LEN) != SUCCESS) {
        DEBUG_PRINT("Error reading IV from header\n");
        return FAIL;
    }

    return SUCCESS;
}

int encrypt_database(FILE *db, const char *master_password, Buffer *encrypted) {
    Buffer file_body = { 0 };
    Header header = { 0 };
    size_t body_size = 0;

    if (read_header(db, &header) != SUCCESS) {
        DEBUG_PRINT("Error reading in header from database\n");
        return FAIL;
    }

    body_size = get_file_size(db) - HEADER_SIZE;
    if (body_size == 0) {
        return SUCCESS;
    }
    else if (body_size < 0) {
        DEBUG_PRINT("Error reading file size\n");
        return FAIL;
    }
    
    file_body.size = body_size;
    file_body.bytes = (unsigned char *)calloc(file_body.size, sizeof(unsigned char));

    if (read_file(db, &file_body, HEADER_SIZE) != SUCCESS) {
        DEBUG_PRINT("Error reading file into buffer\n");
        goto error;
    }

    encrypted->size = get_nearest_blocksize(file_body.size, AES_256_BLK_SZ);
    encrypted->bytes = (unsigned char *)calloc(encrypted->size, sizeof(unsigned char));

    if (encrypt(&file_body, encrypted, master_password, &header) != SUCCESS) {
        DEBUG_PRINT("Error encrypting database\n");
        goto error;
    }
    
    free(file_body.bytes);
    file_body.bytes = NULL;

    return SUCCESS;

error:
    if (file_body.bytes != NULL) {
        free(file_body.bytes);
        file_body.bytes = NULL;
    }
    return FAIL;
}

int write_encrypted_database(FILE *db, const char *master_password) {
    Buffer encrypted = { 0 };

    if (encrypt_database(db, master_password, &encrypted) != SUCCESS) {
        DEBUG_PRINT("Error encrypting database\n");
        goto error;
    } 

    if (write_file(db, &encrypted, HEADER_SIZE, SEEK_SET) != SUCCESS) {
        DEBUG_PRINT("Error writing encrypted database to file\n");
        goto error;
    }

    free(encrypted.bytes);
    encrypted.bytes = NULL;

    return SUCCESS;

error:
    if (encrypted.bytes != NULL) {
        free(encrypted.bytes);
        encrypted.bytes = NULL;
    }
    return FAIL;
}

int read_encrypted_content(FILE *db, Buffer *encrypted) {
    if (read_file(db, encrypted, HEADER_SIZE) != SUCCESS) {
        DEBUG_PRINT("Error reading encrypted content from header\n");
        return FAIL;
    }

    return SUCCESS;
}

int decrypt_database(FILE *db, const char *master_password, Buffer *decrypted) {
    Buffer encrypted = { 0 };
    Header header = { 0 };

    if (read_header(db, &header) != SUCCESS) {
        DEBUG_PRINT("Error reading in header from database\n");
        return FAIL;
    }

    encrypted.size = get_file_size(db) - HEADER_SIZE;
    if (encrypted.size == 0) {
        return SUCCESS;
    }
    else if (encrypted.size < 0) {
        DEBUG_PRINT("Error in decrypt_database(): missing header\n");
        return FAIL;
    }

    encrypted.bytes = (unsigned char *)calloc(encrypted.size, sizeof(unsigned char));

    if (read_encrypted_content(db, &encrypted) != SUCCESS) {
        DEBUG_PRINT("Error reading encrypted content from database\n");
        goto error;
    }

    decrypted->size = encrypted.size;
    decrypted->bytes = (unsigned char *)calloc(decrypted->size, sizeof(unsigned char));

    if (decrypt(&encrypted, decrypted, master_password, &header) != SUCCESS) {
        DEBUG_PRINT("Error decrypting database\n");
        goto error;
    }

    free(encrypted.bytes);
    encrypted.bytes = NULL;

    return SUCCESS;

error:
    if (encrypted.bytes != NULL) {
        free(encrypted.bytes);
        encrypted.bytes = NULL;
    }
    return FAIL;
}

int write_decrypted_database(FILE *db, const char *master_password) {
    Buffer decrypted = { 0 };

    if (decrypt_database(db, master_password, &decrypted) != SUCCESS) {
        DEBUG_PRINT("Error decrypting database\n");
        goto error;
    }

    // Remove encrypted content
    if (ftruncate(fileno(db), HEADER_SIZE) != 0) {
        perror("Error truncating file\n");
        return FAIL;
    }
    
    // Write decrypted content
    if (write_file(db, &decrypted, HEADER_SIZE, SEEK_SET) != SUCCESS) {
        DEBUG_PRINT("Error writing decrypted content to database\n");
        goto error;
    }

    free(decrypted.bytes);
    decrypted.bytes = NULL;

    return SUCCESS;

error:
    if (decrypted.bytes != NULL) {
        free(decrypted.bytes);
        decrypted.bytes = NULL;
    }
    return FAIL;
}


int handle_add_new_credentials(FILE *db, Entry *entry, bool generate) {
    Buffer new_pass_buf = { 0 };
    unsigned char *entry_str = NULL;
    char generated_password[MAX_PASSWORD_LEN] = { 0 };
    const char *password = NULL;

    if (generate) {
        generate_password(generated_password);
    }

    password = generate ? generated_password : entry->password;

    /* Entry is site_name + ':' + new_password + '\n'
    /* snprintf will automatically add null-terminator so  
    /* add extra byte so newline does not get truncated
    */
    size_t entry_len = strlen(entry->site_name) + strlen(password) + strlen(entry->username) + 3 * sizeof(char) + 1;
    entry_str = (unsigned char *)calloc(entry_len, sizeof(unsigned char));
    snprintf(entry_str, entry_len, "%s:%s:%s\n", entry->site_name, entry->username, password);

    new_pass_buf.bytes = (unsigned char *)entry_str;
    new_pass_buf.size = entry_len - 1; // Subtracting one so null terminator does not get written

    if (write_file(db, &new_pass_buf, 0, SEEK_END) != SUCCESS) {
        DEBUG_PRINT("Error appending new password to end of database\n");
        goto error;
    }

    free(new_pass_buf.bytes);
    new_pass_buf.bytes = NULL;
    return SUCCESS;

error:
    free(new_pass_buf.bytes);
    new_pass_buf.bytes = NULL;
    return FAIL;
}

int append_header(FILE *db, Header *header) {
    // Generate random 128-bit salt
    if (init_random(header->salt, SALT_LEN) != SUCCESS) {
        DEBUG_PRINT("Error in append_header(): error generating random bytes\n");
        return FAIL;
    }

    // Append salt
    if (write_bytes(db, header->salt, SALT_LEN) != SUCCESS) {
        DEBUG_PRINT("Error in initialize_database(): error writing salt to file\n");
        return FAIL;
    }

    // Generate random 16-bit IV
    if (init_random(header->iv, IV_LEN) != SUCCESS) {
        DEBUG_PRINT("Error in encrypt_database(): error generating IV\n");
        return FAIL;
    }

    // Write IV to file
    if (write_bytes(db, header->iv, IV_LEN) != SUCCESS) {
        DEBUG_PRINT("Error in initialize_database(): error writing IV to file\n");
        return FAIL;
    }

    return SUCCESS;
}

// Returns offset in file where password entry is located
ssize_t find_entry(FILE *db, Entry *entry) {
    char *line = NULL, *url = NULL;
    size_t len = 0;
    ssize_t num_read = 0, total_read = 0;
    bool found = false;

    if (fseek(db, HEADER_SIZE, SEEK_SET) != 0) {
        perror("Error seeking to beginning of content");
        return FAIL;
    }

    while (!found && ((num_read = getline(&line, &len, db)) != -1)) {
        // read until colon
        url = strtok(line, ":");
        if (strncmp(entry->site_name, url, strlen(url)) == 0) {
            found = true;
        }

        free(line);
        line = NULL;
        total_read += num_read;
    }

    free(line);
    line = NULL;

    /*
    /* Need to offset by HEADER_SIZE in case where 
    /* located password is first entry
    */
    if (found) {
        return (total_read - num_read) + HEADER_SIZE;
    }

    // Password not found
    return FAIL;
}

int handle_retrieve_credentials(FILE *db, Entry *entry) {
    ssize_t offset = 0;
    ssize_t num_read = 0;
    char *line = NULL, *url = NULL, *username = NULL, *password = NULL;
    size_t len = 0;

    if ((offset = find_entry(db, entry)) == FAIL) {
        return FAIL;
    }

    if (fseek(db, offset, SEEK_SET) != 0) {
        perror("Error in handle_retrieve_credentials()");
        return FAIL;
    }

    if ((num_read = getline(&line, &len, db)) != -1) {
        url = strtok(line, ":");
        username = strtok(NULL, ":");
        password = strtok(NULL, "\n");
    
        strcpy(entry->username, username);
        strcpy(entry->password, password);

        free(line);
        line = NULL;

        return SUCCESS;
    }
    else {
        perror("Error in handle_retrieve_credentials(): ");
    }

    free(line);
    line = NULL;
    return FAIL;
}

int handle_delete_credentials(FILE *db, Entry *entry) {
    Buffer write_buf = { 0 };
    char *line = NULL, *url = NULL;
    ssize_t num_read = 0;
    size_t len = 0, line_len = 0, decrypted_sz = 0, 
            to_write = 0, offset = 0;
    char *copy_line = NULL;

    // Get size of decrypted content
    decrypted_sz = get_file_size(db) - HEADER_SIZE;
    write_buf.bytes = (unsigned char *)malloc(decrypted_sz);

    // Read from beginning of decrypted content
    if (fseek(db, HEADER_SIZE, SEEK_SET) != 0) {
        perror("Error seeking to beginning of content");
        return FAIL;
    }

    /*
    /* Compare line by line URL; if match, ignore;
    /* else, copy line to write buffer
    */
    while ((num_read = getline(&line, &len, db)) != -1) {
        line_len = strlen(line);
        copy_line = (char *)malloc(line_len);
        memcpy(copy_line, line, strlen(line));

        url = strtok(line, ":");
        if (url != NULL && strncmp(entry->site_name, url, strlen(entry->site_name)) != 0) {
            memcpy(write_buf.bytes + offset, copy_line, line_len);
            offset += line_len;
            to_write += line_len;
        }

        free(copy_line);
        free(line);
        line = NULL;
    }

    free(line);
    line = NULL;

    write_buf.size = to_write;

    // Remove old decrypted passwords
    if (ftruncate(fileno(db), HEADER_SIZE) != 0) {
        perror("Error truncating file\n");
        return FAIL;
    }

    if (write_buf.size > 0) {
        if (write_file(db, &write_buf, HEADER_SIZE, SEEK_SET) != SUCCESS) {
            DEBUG_PRINT("Error in handle_delete_password(): error writing buffer to file\n");
            goto error;
        }
    }
    

    free(write_buf.bytes);
    return SUCCESS;

error:
    free(write_buf.bytes);
    return FAIL;
}