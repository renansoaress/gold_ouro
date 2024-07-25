#include "m_go.h"

void calculate_sha256(const unsigned char *input, size_t input_len, unsigned char output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 para SHA-256, 1 para SHA-224
    mbedtls_sha256_update(&ctx, input, input_len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
}

void calculate_sha1(const unsigned char *input, size_t input_len, unsigned char output[20])
{
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, input, input_len);
    mbedtls_sha1_finish(&ctx, output);
    mbedtls_sha1_free(&ctx);
}

void calculate_md5(const unsigned char *input, size_t input_len, unsigned char output[16])
{
    mbedtls_md5_context ctx;
    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, input, input_len);
    mbedtls_md5_finish(&ctx, output);
    mbedtls_md5_free(&ctx);
}

void encrypt_string(const char *input, const char *key, const char *iv, unsigned char **output, size_t *output_len)
{
    unsigned char sha256_key[32];
    calculate_sha256((const unsigned char *)key, strlen(key), sha256_key);
    printf("SHA256 Key: (");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", sha256_key[i]);
    }
    printf(")\n");
    // ESP_LOG_BUFFER_HEX("SHA256 KEY", sha256_key, 32);

    unsigned char md5_iv[16];
    calculate_md5((const unsigned char *)iv, strlen(iv), md5_iv);
    printf("MD5 IV: (");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", md5_iv[i]);
    }
    printf(")\n");
    // ESP_LOG_BUFFER_HEX("MD5 IV", md5_iv, 16);

    size_t input_len = strlen(input);
    size_t padded_input_len = (input_len / 16 + 1) * 16;

    unsigned char padded_input[padded_input_len];
    memset(padded_input, 0, sizeof(padded_input));
    // unsigned char *padded_input = (unsigned char *)malloc(padded_input_len);
    // if (!padded_input)
    // {
    //     printf("[encrypt_string] Failed to allocate memory\n");
    //     return;
    // }

    memcpy(padded_input, input, input_len);

    // add PKCS#5 padding
    uint8_t padding_value = padded_input_len - input_len;
    for (size_t i = input_len; i < padded_input_len; i++)
    {
        padded_input[i] = padding_value;
    }

    // *output = (unsigned char *)malloc(padded_input_len);
    *output = (unsigned char *)calloc(padded_input_len, sizeof(unsigned char));
    if (!(*output))
    {
        printf("[encrypt_string] Failed to allocate memory for output\n");
        // free(padded_input);
        return;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, sha256_key, 256);
    if (ret != 0)
    {
        printf("Falha ao definir chave de criptografia: -0x%04x\n", -ret);
        mbedtls_aes_free(&aes);
        return;
    }

    // ECB
    // mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (unsigned char *)padded_input, encrypt_output);

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_input_len, md5_iv, padded_input, *output);
    if (ret != 0)
    {
        printf("Falha na criptografia CBC: -0x%04x\n", -ret);
        mbedtls_aes_free(&aes);
        return;
    }
    // ESP_LOG_BUFFER_HEX("cbc_encrypt", *output, padded_input_len);

    *output_len = padded_input_len;

    // free(padded_input);
    mbedtls_aes_free(&aes);

    // unsigned char base64_output[128]; // Buffer para a saída base64
    // size_t base64_output_len;
    // int ret = mbedtls_base64_encode(base64_output, sizeof(base64_output), &base64_output_len, *output, *output_len);
    // if (ret == 0)
    // {
    //     printf("Base64 encoded output[%d]: %.*s\n", (int)base64_output_len, (int)base64_output_len, base64_output);
    // }
    // else
    // {
    //     printf("Failed to encode in base64\n");
    // }
}

void decrypt_string(const unsigned char *input, size_t input_len, const char *key, const char *iv, char **output, size_t *output_len)
{
    unsigned char sha256_key[32];
    calculate_sha256((const unsigned char *)key, strlen(key), sha256_key);
    printf("SHA256 Key: (");
    for (int i = 0; i < 32; i++)
    {
        printf("%02X", sha256_key[i]);
    }
    printf(")\n");
    // ESP_LOG_BUFFER_HEX("SHA256 KEY", sha256_key, 32);

    unsigned char md5_iv[16];
    calculate_md5((const unsigned char *)iv, strlen(iv), md5_iv);
    // ESP_LOG_BUFFER_HEX("MD5 IV", md5_iv, 16);

    unsigned char decrypt_output[input_len];
    memset(decrypt_output, 0, sizeof(decrypt_output));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_dec(&aes, sha256_key, 256);
    if (ret != 0)
    {
        printf("Falha ao definir chave de criptografia: -0x%04x\n", -ret);
        mbedtls_aes_free(&aes);
        return;
    }
    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, md5_iv, input, decrypt_output);
    if (ret != 0)
    {
        printf("Falha na criptografia CBC: -0x%04x\n", -ret);
        mbedtls_aes_free(&aes);
        return;
    }
    mbedtls_aes_free(&aes);
    // ESP_LOG_BUFFER_HEX("cbc_decrypt", decrypt_output, input_len);

    // remove PKCS#5 padding
    uint8_t padding_value = decrypt_output[input_len - 1];
    if (padding_value > 16)
    {
        printf("[decrypt_string] Invalid padding value\n");
        // free(decrypt_output);
        return;
    }
    *output_len = input_len - padding_value;
    // *output = (char *)malloc(*output_len + 1);
    *output = (char *)calloc(*output_len + 1, sizeof(char));
    if (!(*output))
    {
        printf("[decrypt_string] Failed to allocate memory for output\n");
        // free(decrypt_output);
        return;
    }
    memcpy(*output, decrypt_output, *output_len);
    (*output)[*output_len] = '\0';
}