#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "crypto.h"


int derive_key(const char *master_password, const unsigned char *salt, unsigned char *key) {
    // Derive symmetric key from salt and master password
    if (PKCS5_PBKDF2_HMAC(master_password, strlen(master_password), salt, SALT_LEN, KDF_ITERATIONS, EVP_sha256(), KEY_LEN, key) != SUCCESS) {
        DEBUG_PRINT("Error in derive_key(): error in key derivation function\n");
        return FAIL;
    }

    return SUCCESS;
}


int encrypt(Buffer *inb, Buffer *outb, const char *master_password, const Header *header) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0;
    int final_len = 0;
    unsigned char key[KEY_LEN] = { 0 };

    if (derive_key(master_password, header->salt, key) != SUCCESS) {
        DEBUG_PRINT("Error in initialize_database(): error deriving key\n");
        return FAIL;
    }
    
    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        DEBUG_PRINT("Error in encrypt_database(): error intializing cipher context\n");
        return FAIL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, header->iv) != SUCCESS) {
        DEBUG_PRINT("Error in encrypt_database(): error intializing encryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (EVP_EncryptUpdate(ctx, outb->bytes, &out_len, inb->bytes, (int)inb->size) != SUCCESS) {
        DEBUG_PRINT("Error in encrypt_database(): error in encryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (EVP_EncryptFinal_ex(ctx, (outb->bytes + out_len), &final_len) != SUCCESS) {
        DEBUG_PRINT("Error in encrypt_database(): error finalizing encryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    outb->size = (out_len + final_len);

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;

error:
    EVP_CIPHER_CTX_free(ctx);
    return FAIL;
}


int decrypt(Buffer *inb, Buffer *outb, const char *master_password, const Header *header) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0;
    int final_len = 0;

    unsigned char key[KEY_LEN] = { 0 };

    if (derive_key(master_password, header->salt, key) != SUCCESS) {
        DEBUG_PRINT("Error in decrypt(): error deriving key\n");
        return FAIL;
    }
    
    ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, header->iv) != SUCCESS) {
        DEBUG_PRINT("Error in decrypt(): intializing decryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (EVP_DecryptUpdate(ctx, outb->bytes, &out_len, inb->bytes, (int)inb->size) != SUCCESS) {
        DEBUG_PRINT("Error in decrypt(): updating decryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (EVP_DecryptFinal_ex(ctx, (outb->bytes + out_len), &final_len) != SUCCESS) {
        DEBUG_PRINT("Error in decrypt(): finalizing decryption operation\n");
        ERR_print_errors_fp(stderr);
        goto error;
    }

    outb->size = (final_len + out_len);

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;

error:
    EVP_CIPHER_CTX_free(ctx);
    return FAIL;
}

size_t get_nearest_blocksize(size_t in, size_t blocksize) {
    return in + blocksize - (in % blocksize);
}

int init_random(unsigned char *bytes, size_t size) {
    if (RAND_bytes(bytes, size) != SUCCESS) {
        DEBUG_PRINT("Error in init_random(): error generating random bytes\n");
        ERR_print_errors_fp(stderr);
        return FAIL;
    }

    return SUCCESS;
}

int generate_password(char *password) {
    unsigned char buf[MAX_PASSWORD_LEN] = {0};
    const char *charset = CHARSET;
    size_t charset_sz = strlen(charset);

    if (RAND_bytes(buf, sizeof(buf)) != SUCCESS) {
        DEBUG_PRINT("Error in generate_password(): error generating random bytes\n");
        ERR_print_errors_fp(stderr);
        return FAIL;
    }

    for (size_t i = 0; i < MAX_PASSWORD_LEN; ++i) {
        password[i] = charset[buf[i] % charset_sz];
    }    

    return SUCCESS;
}