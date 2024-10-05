#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert a character to an 8-bit binary string
void char_to_binary(char c, char *binary) {
    for (int i = 7; i >= 0; i--) {
        binary[7 - i] = ((c >> i) & 1) + '0';
    }
    binary[8] = '\0';
}

// Function to generate Hamming(7,4) code
void generate_hamming_code(const char *data_bits, char *hamming_code) {
    int data[4];
    for (int i = 0; i < 4; i++) {
        data[i] = data_bits[i] - '0';
    }

    // Calculate parity bits
    int p1 = data[0] ^ data[1] ^ data[3];
    int p2 = data[0] ^ data[2] ^ data[3];
    int p3 = data[1] ^ data[2] ^ data[3];

    // Construct the Hamming code
    hamming_code[0] = p1 + '0';
    hamming_code[1] = p2 + '0';
    hamming_code[2] = data[0] + '0';
    hamming_code[3] = p3 + '0';
    hamming_code[4] = data[1] + '0';
    hamming_code[5] = data[2] + '0';
    hamming_code[6] = data[3] + '0';
    hamming_code[7] = '\0';
}

// Function to detect and correct a single-bit error in a Hamming(7,4) code
void detect_and_correct_error(char *hamming_code) {
    int hamming[7];
    for (int i = 0; i < 7; i++) {
        hamming[i] = hamming_code[i] - '0';
    }

    // Calculate parity checks
    int p1 = hamming[0] ^ hamming[2] ^ hamming[4] ^ hamming[6];
    int p2 = hamming[1] ^ hamming[2] ^ hamming[5] ^ hamming[6];
    int p3 = hamming[3] ^ hamming[4] ^ hamming[5] ^ hamming[6];

    // Calculate error position
    int error_pos = p1 * 1 + p2 * 2 + p3 * 4;

    // Correct the error if there is one
    if (error_pos != 0) {
        hamming[error_pos - 1] ^= 1;
    }

    // Update the corrected Hamming code
    for (int i = 0; i < 7; i++) {
        hamming_code[i] = hamming[i] + '0';
    }
}

// Function to encode a binary string using Hamming(7,4) encoding
void encode_binary_string(const char *data_bits, char *encoded_string) {
    size_t len = strlen(data_bits);
    char hamming_code[8];
    char *encoded_ptr = encoded_string;

    for (size_t i = 0; i < len; i += 4) {
        generate_hamming_code(data_bits + i, hamming_code);
        memcpy(encoded_ptr, hamming_code, 7);
        encoded_ptr += 7;
    }
    *encoded_ptr = '\0';
}

// Function to decode a binary string encoded with Hamming(7,4) and correct errors
void decode_binary_string(const char *encoded_string, char *decoded_string) {
    size_t len = strlen(encoded_string);
    char hamming_code[8];
    char corrected_code[5];
    char *decoded_ptr = decoded_string;

    for (size_t i = 0; i < len; i += 7) {
        strncpy(hamming_code, encoded_string + i, 7);
        hamming_code[7] = '\0';
        detect_and_correct_error(hamming_code);

        // Extract the original data bits
        corrected_code[0] = hamming_code[2];
        corrected_code[1] = hamming_code[4];
        corrected_code[2] = hamming_code[5];
        corrected_code[3] = hamming_code[6];
        memcpy(decoded_ptr, corrected_code, 4);
        decoded_ptr += 4;
    }
    *decoded_ptr = '\0';
}

// Main function for CLI tool
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <encode|decode> [data]\n", argv[0]);
        return 1;
    }

    char *operation = argv[1];
    char *input_string = NULL;
    size_t buffer_size = 1024;
    size_t total_read = 0;
    size_t bytes_read;

    // Allocate initial buffer
    input_string = malloc(buffer_size);
    if (!input_string) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Read from stdin if data is available
    while ((bytes_read = fread(input_string + total_read, 1, buffer_size - total_read, stdin)) > 0) {
        total_read += bytes_read;
        // Reallocate buffer if necessary
        if (total_read == buffer_size) {
            buffer_size *= 2;
            input_string = realloc(input_string, buffer_size);
            if (!input_string) {
                fprintf(stderr, "Memory reallocation failed\n");
                return 1;
            }
        }
    }

    // Null-terminate the string
    input_string[total_read] = '\0';

    if (total_read == 0 && argc == 3) {
        // Use command-line argument if no stdin input
        input_string = argv[2];
    } else if (total_read == 0) {
        fprintf(stderr, "No input data provided.\n");
        free(input_string);
        return 1;
    }

    if (strcmp(operation, "encode") == 0) {
        // Convert the input string to a binary string
        size_t input_len = strlen(input_string);
        char *binary_string = (char *)malloc(input_len * 8 + 1);
        if (!binary_string) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_string);
            return 1;
        }
        char *binary_ptr = binary_string;
        for (size_t i = 0; i < input_len; i++) {
            char binary_char[9];
            char_to_binary(input_string[i], binary_char);
            memcpy(binary_ptr, binary_char, 8);
            binary_ptr += 8;
        }
        *binary_ptr = '\0';

        // Encode the binary string
        char *encoded_string = (char *)malloc(input_len * 14 + 1);  // Rough estimate for encoded size
        if (!encoded_string) {
            fprintf(stderr, "Memory allocation failed\n");
            free(binary_string);
            free(input_string);
            return 1;
        }
        encode_binary_string(binary_string, encoded_string);
        printf("%s", encoded_string);

        free(binary_string);
        free(encoded_string);
    } else if (strcmp(operation, "decode") == 0) {
        // Decode the binary string
        size_t input_len = strlen(input_string);
        char *corrected_string = (char *)malloc(input_len / 7 * 4 + 1);
        if (!corrected_string) {
            fprintf(stderr, "Memory allocation failed\n");
            free(input_string);
            return 1;
        }
        decode_binary_string(input_string, corrected_string);

        // Convert the corrected binary string back to text
        size_t corrected_len = strlen(corrected_string);
        char *decoded_text = (char *)malloc(corrected_len / 8 + 1);
        if (!decoded_text) {
            fprintf(stderr, "Memory allocation failed\n");
            free(corrected_string);
            free(input_string);
            return 1;
        }
        char *decoded_ptr = decoded_text;
        for (size_t i = 0; i < corrected_len; i += 8) {
            char byte_str[9];
            strncpy(byte_str, corrected_string + i, 8);
            byte_str[8] = '\0';
            *decoded_ptr++ = (char)strtol(byte_str, NULL, 2);
        }
        *decoded_ptr = '\0';
        printf("%s", decoded_text);

        free(corrected_string);
        free(decoded_text);
    } else {
        fprintf(stderr, "Invalid operation. Use 'encode' or 'decode'.\n");
        free(input_string);
        return 1;
    }

    free(input_string);
    return 0;
}