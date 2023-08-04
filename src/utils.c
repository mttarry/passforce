#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "utils.h"


int append_newline(FILE *fp) {
    size_t bytes_written = 0;
    char newline = '\n';

    bytes_written = fwrite(&newline, sizeof(char), sizeof(newline), fp);
    
    if (bytes_written != sizeof(newline)) {
        perror("Error writing newline");
        return FAIL;
    }

    return SUCCESS;
}

int write_bytes(FILE *fp, const unsigned char *bytes, size_t num_bytes) {
    size_t bytes_written = 0;

    bytes_written = fwrite(bytes, sizeof(unsigned char), num_bytes, fp);
    if (bytes_written != num_bytes) {
        perror("Error writing bytes to file");
        return FAIL;
    }

    return SUCCESS;
}

size_t get_file_size(FILE *fp) {
    size_t file_size = 0;
    
    if (fseek(fp, 0L, SEEK_END) != 0) {
        perror("Error seeking to end of file");
        return FAIL;
    }

    file_size = ftell(fp);

    rewind(fp);

    return file_size;
}

int read_file(FILE *fp, Buffer *buf, size_t offset) {
    size_t bytes_read = 0;

    fseek(fp, offset, SEEK_SET);
    
    bytes_read = fread(buf->bytes, sizeof(unsigned char), buf->size, fp);
    if (bytes_read != buf->size) {
        perror("Error reading file into buffer");
        return FAIL;
    }

    return SUCCESS;
}


int write_file(FILE *fp, Buffer *buf, size_t offset, int whence) {
    size_t bytes_written = 0;

    fseek(fp, offset, whence);

    bytes_written = fwrite(buf->bytes, sizeof(unsigned char), buf->size, fp);
    if (bytes_written != buf->size) {
        perror("Error writing bytes to file");
        return FAIL;
    }

    return SUCCESS;
}


int str_check_len(const char *str, size_t len) {
    if (str != NULL) {
        return (strlen(str) <= len);
    }
    
    return SUCCESS;
}

