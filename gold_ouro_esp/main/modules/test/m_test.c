#include "m_test.h"

void test()
{
    printf(">>> Teste de Criptografia LOCAL! <<<\n\n");
    int64_t count = 0;
    // char msg[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
    char msg[] = "oii";
    char enc_key[] = "minha senha secreta";
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(2000));

        int64_t iv_64 = generate_random_14_digit_number();
        // int64_t iv_64 = get_timestamp();
        // int64_t iv_64 = 999999999999999;
        char iv_hex[15] = {};
        sprintf(iv_hex, "%014llX", iv_64);

        printf("%s    ***IV: (%s)***\n", C_WHT, iv_hex);

        // Encrypt the message
        unsigned char *encrypted_msg = NULL;
        size_t encrypted_len = 0;
        encrypt_string(msg, enc_key, iv_hex, &encrypted_msg, &encrypted_len);
        printf("> Encrypt message[%d]: (%s)\n", encrypted_len, encrypted_msg);

        // iv gold ouro
        char iv_ascii[8] = {0};
        int iv_ascii_len = 7;
        hex_to_ascii(iv_hex, iv_ascii);
        size_t new_msg_size = encrypted_len + 9;
        unsigned char new_msg[new_msg_size];
        new_msg[0] = 0x5E; // ^
        memcpy(new_msg + 1, iv_ascii, iv_ascii_len);
        memcpy(new_msg + 1 + iv_ascii_len, encrypted_msg, encrypted_len);
        new_msg[new_msg_size - 1] = 0x24; // $
        printf("Encrypt new message[%d]: (%s)\n", new_msg_size, new_msg);
        printf("Encrypt new message HEX: (");
        for (int i = 0; i < new_msg_size; i++)
        {
            printf("%02X", new_msg[i]);
        }
        printf(")\n");

        ////////////////////////////////////////////////////////////////////////

        // Decrypt the message
        char *decrypted_msg = NULL;
        size_t decrypted_len = 0;
        bool isValid = new_msg[0] == '^' && new_msg[new_msg_size - 1] == '$';
        if (isValid)
        {
            char hex_msg[(new_msg_size * 2) + 1];
            ascii_to_hex(new_msg, new_msg_size, hex_msg);
            char iv_recv[15] = {0};
            substring(iv_recv, hex_msg, 2, 16);

            char iv[strlen(iv_recv) + 8 + 1];
            sprintf(iv, "GOLD%sOURO", iv_recv);

            char msg_recv[strlen(hex_msg) - strlen(iv_recv) - 4 + 1];
            int msg_size_final = strlen(hex_msg) - 2;
            substring(msg_recv, hex_msg, 16, msg_size_final);

            size_t msg_ascii_size = (strlen(msg_recv) / 2);
            char msg_ascii[msg_ascii_size + 1];
            hex_to_ascii(msg_recv, msg_ascii);
            decrypt_string((unsigned char *)msg_ascii, msg_ascii_size, enc_key, iv, &decrypted_msg, &decrypted_len);
            printf("Decrypted message: [%d](%s)[%c]\n\n\n", decrypted_len, decrypted_msg, decrypted_msg[decrypted_len - 1]);
        }

        if (encrypted_msg)
        {
            free(encrypted_msg);
        }
        if (decrypted_msg)
        {
            free(decrypted_msg);
        }

        count++;
    }
}