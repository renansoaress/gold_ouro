#ifndef GO_H
#define GO_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "esp_log.h"
#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "modules/utils/m_utils.h"

void calculate_sha256(const unsigned char *input, size_t input_len, unsigned char output[32]);
void calculate_sha1(const unsigned char *input, size_t input_len, unsigned char output[20]);
void calculate_md5(const unsigned char *input, size_t input_len, unsigned char output[16]);
void encrypt_string(const char *input, const char *key, const char *iv, unsigned char **output, size_t *output_len);
void decrypt_string(const unsigned char *input, size_t input_len, const char *key, const char *iv, char **output, size_t *output_len);

#endif