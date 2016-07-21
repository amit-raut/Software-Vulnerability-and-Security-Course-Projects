#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>

char* check_path(char* path) {
    char* res_path = realpath(path, NULL);
    if (!res_path) {
        printf("ERROR: unable to resolve path\n");
        return NULL;
    }

    if (strncmp(res_path, "/home", sizeof("/home") - 1)) {
        printf("ERROR: invalid path\n");
        free(res_path);
        return NULL;
    }

    return res_path;
}

int process_cat(char* path) {
    int ret = 1;
    FILE* input = NULL;
    char* res_path = check_path(path);
    if (!res_path) {
        goto out;
    }

    if ((input = fopen(res_path, "r")) == NULL) {
        printf("ERROR: unable to access %s\n", path);
        goto out;
    }

    while (!feof(input)) {
        char buf[4096];
        size_t n = fread(buf, 1, sizeof(buf), input);

        size_t i = 0u;
        while (i < n) {
            size_t m = fwrite(buf + i, 1, n - i, stdout);
            if (!m) {
                printf("ERROR: unable to write contents of %s\n", path);
                goto out;
            }

            i += m;
        }
    }

    ret = 0;

out:
    if (input) {
        fclose(input);
    }

    if (res_path) {
        free(res_path);
    }

    return ret;
}

int process_real_cat(char* path) {
    int ret = 1;
    char buf[4096];
    char* res_path = check_path(path);
    if (!res_path) {
        goto out;
    }

    snprintf(buf, sizeof(buf), "/bin/cat %s", res_path);
    ret = system(buf);

out:
    if (res_path) {
        free(res_path);
    }

    return ret;
}

int process_hash(char* path, uint8_t* hash, size_t* hash_len) {
    int ret = 1;
    FILE* input = NULL;
    char buf[4096];
    const EVP_MD* md;
    EVP_MD_CTX* md_ctxt = NULL;

    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("sha256");
    md_ctxt = EVP_MD_CTX_create();

    EVP_DigestInit_ex(md_ctxt, md, NULL);

    char* res_path = check_path(path);
    if (!res_path) {
        goto out;
    }

    if ((input = fopen(res_path, "r")) == NULL) {
        printf("ERROR: unable to access %s\n", path);
        goto out;
    }

    while (!feof(input)) {
        size_t n = fread(buf, 1, sizeof(buf), input);
        EVP_DigestUpdate(md_ctxt, buf, n);
    }

    EVP_DigestFinal_ex(md_ctxt, hash, (unsigned int*) hash_len);

    ret = 0;

out:
    if (md_ctxt) {
        EVP_MD_CTX_destroy(md_ctxt);
    }

    if (input) {
        fclose(input);
    }

    if (res_path) {
        free(res_path);
    }

    return ret;
}

int digittoint(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return 0;
}

int process_verify(char* path, char* hash) {
    size_t computed_hash_len = 0u;
    uint8_t computed_hash[EVP_MAX_MD_SIZE];
    uint8_t hash_buf[EVP_MAX_MD_SIZE * 2];
    if (process_hash(path, computed_hash, &computed_hash_len)) {
        return 1;
    }

    strcpy((char*) hash_buf, hash);
    for (size_t i = 0; i < computed_hash_len; i++) {
        if (!isxdigit(hash_buf[2*i]) || !isxdigit(hash_buf[2*i+1])) {
            printf(
                "ERROR: invalid hash byte (%c%c)\n",
                hash_buf[2*i],
                hash_buf[2*i+1]);
            return 1;
        }

        hash_buf[i] =
            (digittoint(hash_buf[2*i]) << 4)
            | digittoint(hash_buf[2*i+1]);
    }

    if (!memcmp(computed_hash, hash_buf, computed_hash_len)) {
        printf("OK\n");
    } else {
        printf("MISMATCH\n");
    }

    return 0;
}

int process_command(int argc, char* cmd, char** argv) {
    if (argc >= 1 && !strcmp(cmd, "cat")) {
        return process_cat(argv[0]);
    } else if (argc >= 1 && !strcmp(cmd, "realcat")) {
        return process_real_cat(argv[0]);
    } else if (argc >= 1 && !strcmp(cmd, "hash")) {
        size_t hash_len = 0u;
        uint8_t hash[EVP_MAX_MD_SIZE];
        if (process_hash(argv[0], hash, &hash_len)) {
            return 1;
        }

        for (size_t i = 0; i < hash_len; i++) {
            printf("%02x", hash[i]);
        }

        printf("  %s\n", argv[0]);

        return 0;
    } else if (argc >= 2 && !strcmp(cmd, "verify")) {
        return process_verify(argv[0], argv[1]);
    } else {
        printf("ERROR: invalid command (%s)\n", cmd);
        return 1;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    return process_command(argc - 2, argv[1], argv + 2);
}
