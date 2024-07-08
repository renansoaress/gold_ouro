#include "m_utils.h"

void substring(char *dest, const char *str, int start, int end)
{
    int str_length = strlen(str);
    if (start < 0 || end < 0 || start >= str_length || start >= end)
    {
        dest[0] = '\0';
        return;
    }
    int sub_length = (end - start);
    if (end > str_length)
    {
        sub_length = str_length - start;
    }
    strncpy(dest, str + start, sub_length);
    dest[sub_length] = '\0';
}

void ascii_to_hex(const unsigned char *ascii_array, int ascii_length, char *hex_array)
{
    for (int i = 0, j = 0; i < ascii_length; ++i, j += 2)
    {
        sprintf(hex_array + j, "%02X", ascii_array[i]);
    }
}

void hex_to_ascii(const char *hex_string, char *ascii_string)
{
    int len = strlen(hex_string);

    for (int i = 0; i < len; i += 2)
    {
        char hex[3] = {hex_string[i], hex_string[i + 1], '\0'};
        long value = strtol(hex, NULL, 16);
        ascii_string[i / 2] = value;
        // printf("(%d)Hex: %s, ASCII: (%ld)(%c) (%c)-(%d)\n",i, hex, value, (char)value, ascii_string[i / 2], sizeof(ascii_string));
    }
}

// char datetime_str[32];
// get_current_time(datetime_str, sizeof(datetime_str));
void get_current_time(char *datetime_str, size_t max_len)
{
    // Verificar se o buffer fornecido é válido
    if (datetime_str == NULL || max_len < 24)
    {
        return;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm timeinfo;
    localtime_r(&tv.tv_sec, &timeinfo);
    strftime(datetime_str, max_len, "%Y-%m-%dT%H:%M:%S", &timeinfo);
    snprintf(datetime_str + strlen(datetime_str), max_len - strlen(datetime_str), ".%03dZ", (int)(tv.tv_usec / 1000));
}

int64_t get_timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL));
}

int64_t generate_random_14_digit_number()
{
    srand((unsigned int)time(NULL));
    int64_t random_number = ((int64_t)rand() * RAND_MAX + rand()) % 90000000000000LL + 10000000000000LL;

    return random_number;
}