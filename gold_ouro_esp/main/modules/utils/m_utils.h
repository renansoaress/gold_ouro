#ifndef UTILS_H
#define UTILS_H

#include "esp_system.h"
#include "esp_log.h"
#include "esp_sntp.h"

#define C_NRM "\x1B[0m"
#define C_RED "\x1B[31m"
#define C_GRN "\x1B[32m"
#define C_YEL "\x1B[33m"
#define C_BLU "\x1B[34m"
#define C_MAG "\x1B[35m"
#define C_CYN "\x1B[36m"
#define C_WHT "\x1B[37m"

void substring(char *dest, const char *src, int start, int len);

void ascii_to_hex(const unsigned char *ascii_array, int ascii_length, char *hex_array);

void hex_to_ascii(const char *hex_string, char *ascii_string);

void get_current_time(char *datetime_str, size_t max_len);

int64_t get_timestamp(void);

int64_t generate_random_14_digit_number();

#endif