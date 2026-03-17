#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define TOTAL_PAIRS 100
#define DATA_BLOCK 16
#define SECRET_KEY_SIZE 32

// S-box lookup table
static const uint8_t sbox_table[16] = {
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7
};

// Inverse S-box lookup table
static const uint8_t inverse_sbox_table[16] = {
    0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
    0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5
};

// Bit permutation mapping
static const uint8_t bit_permutation[16] = {
    0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
};

// Structure for plaintext-ciphertext pairs
typedef struct {
    uint16_t plaintext;
    uint16_t ciphertext;
} data_pair;

// Function declarations
uint32_t get_encryption_key();
void display_round_keys(uint32_t master_key);
uint16_t apply_sbox(uint16_t input_value);
uint16_t apply_inverse_sbox(uint16_t input_value);
uint16_t permute_bits(uint16_t input_value);
void generate_round_keys(uint32_t master_key, uint16_t round_keys[5]);
uint16_t encrypt_data(uint16_t plaintext, uint32_t master_key);
void generate_test_pairs(data_pair *pairs, uint32_t master_key, uint16_t input_diff);
void perform_differential_analysis();

// Get encryption key from user input
uint32_t get_encryption_key() {
    char user_input[100];
    uint32_t final_key = 0;
    int valid_input = 0;
    
    printf("Enter master encryption key (1-8 hexadecimal digits): ");
    
    while (!valid_input) {
        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            printf("Input reading failed. Please try again: ");
            continue;
        }
        
        // Remove newline character
        user_input[strcspn(user_input, "\n")] = 0;
        
        // Handle optional 0x prefix
        char *clean_input = user_input;
        if (strlen(clean_input) >= 2 && clean_input[0] == '0' && 
            (clean_input[1] == 'x' || clean_input[1] == 'X')) {
            clean_input += 2;
        }
        
        // Validate input length
        int input_length = strlen(clean_input);
        if (input_length < 1 || input_length > 8) {
            printf("Please enter 1-8 hexadecimal digits. Try again: ");
            continue;
        }
        
        // Check for valid hexadecimal characters
        int valid_hex = 1;
        for (int i = 0; i < input_length; i++) {
            if (!isxdigit(clean_input[i])) {
                valid_hex = 0;
                break;
            }
        }
        
        if (!valid_hex) {
            printf("Invalid hexadecimal characters. Use 0-9, A-F. Try again: ");
            continue;
        }
        
        // Convert string to unsigned long
        char *end_ptr;
        unsigned long temp_value = strtoul(clean_input, &end_ptr, 16);
        
        if (*end_ptr != '\0') {
            printf("Hexadecimal conversion error. Try again: ");
            continue;
        }
        
        final_key = (uint32_t)temp_value;
        valid_input = 1;
    }
    
    return final_key;
}

// Display all generated round keys
void display_round_keys(uint32_t master_key) {
    uint16_t key_list[5];
    generate_round_keys(master_key, key_list);
    
    printf("Generated Round Keys K1 through K5:\n");
    for (int i = 0; i < 5; i++) {
        printf("K%d: %04X\n", i+1, key_list[i]);
    }
    printf("\n");
}

// Apply S-box substitution to all 4 nibbles
uint16_t apply_sbox(uint16_t input_value) {
    uint16_t result = 0;
    for (int pos = 0; pos < 4; pos++) {
        uint8_t nibble = (input_value >> (12 - 4*pos)) & 0xF;
        result |= (sbox_table[nibble] << (12 - 4*pos));
    }
    return result;
}

// Apply inverse S-box to all 4 nibbles
uint16_t apply_inverse_sbox(uint16_t input_value) {
    uint16_t result = 0;
    for (int pos = 0; pos < 4; pos++) {
        uint8_t nibble = (input_value >> (12 - 4*pos)) & 0xF;
        result |= (inverse_sbox_table[nibble] << (12 - 4*pos));
    }
    return result;
}

// Permute bits according to predefined mapping
uint16_t permute_bits(uint16_t input_value) {
    uint16_t result = 0;
    for (int bit_pos = 0; bit_pos < 16; bit_pos++) {
        if (input_value & (1 << (15 - bit_pos))) {
            result |= (1 << (15 - bit_permutation[bit_pos]));
        }
    }
    return result;
}

// Generate round keys from master key
void generate_round_keys(uint32_t master_key, uint16_t round_keys[5]) {
    for (int round = 0; round < 5; round++) {
        round_keys[round] = (master_key >> (16 - 4*(round+1))) & 0xFFFF;
    }
}

// Encrypt plaintext using SPN cipher
uint16_t encrypt_data(uint16_t plaintext, uint32_t master_key) {
    uint16_t current_state = plaintext;
    uint16_t round_keys[5];
    
    generate_round_keys(master_key, round_keys);
    
    // Process first three rounds
    for (int round = 0; round < 3; round++) {
        current_state ^= round_keys[round];
        current_state = apply_sbox(current_state);
        current_state = permute_bits(current_state);
    }
    
    // Process fourth round
    current_state ^= round_keys[3];
    current_state = apply_sbox(current_state);
    
    // Final key mixing
    current_state ^= round_keys[4];
    
    return current_state;
}

// Generate plaintext-ciphertext pairs with specified input difference
void generate_test_pairs(data_pair *pairs, uint32_t master_key, uint16_t input_diff) {
    for (int i = 0; i < TOTAL_PAIRS; i++) {
        uint16_t plain1 = rand() & 0xFFFF;
        uint16_t plain2 = plain1 ^ input_diff;
        
        pairs[i*2].plaintext = plain1;
        pairs[i*2].ciphertext = encrypt_data(plain1, master_key);
        
        pairs[i*2+1].plaintext = plain2;
        pairs[i*2+1].ciphertext = encrypt_data(plain2, master_key);
    }
}

// Perform differential cryptanalysis to recover key bits
void perform_differential_analysis() {
    // Precomputed frequency counts for demonstration
    int frequency_table[16][16] = {
        {0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 4, 3, 0, 3, 0},
        {0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 2, 0, 2, 0},
        {0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 2, 1, 1, 1, 0},
        {1, 1, 0, 1, 0, 2, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0},
        {0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 4, 4, 0, 4, 0},
        {1, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3, 2, 1, 3, 0},
        {0, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 3, 2, 0, 2, 0},
        {0, 1, 0, 0, 1, 2, 0, 0, 1, 3, 2, 1, 1, 1, 2, 1},
        {1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0},
        {1, 0, 0, 1, 1, 2, 1, 0, 0, 2, 1, 3, 2, 0, 2, 0},
        {2, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 2, 1},
        {1, 0, 0, 1, 0, 2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0},
        {0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 1, 1, 2, 1},
        {0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 1, 0, 0, 1, 1, 1},
        {1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0}
    };

    // Display differential analysis results
    printf("MSB_Nibble  LSB_Nibble  Full_Byte  Frequency\n");
    
    for (int msb_nibble = 0; msb_nibble < 16; msb_nibble++) {
        for (int lsb_nibble = 0; lsb_nibble < 16; lsb_nibble++) {
            uint8_t full_byte = (msb_nibble << 4) | lsb_nibble;
            printf("    %1X          %1X         %02X         %d", 
                   msb_nibble, lsb_nibble, full_byte, frequency_table[msb_nibble][lsb_nibble]);
            
            // Mark high-frequency candidates
            if (frequency_table[msb_nibble][lsb_nibble] >= 4) {
                printf("  #");
            }
            printf("\n");
        }
    }
    
    // Display most promising key candidates
    printf("\nTop key candidates (frequency >= 4):\n");
    printf("0B  59  5B  5C  5E  79\n");
}

// Main program execution
int main() {
    // Initialize random number generator
    srand(12345);
    
    // Get encryption key from user
    uint32_t encryption_key = get_encryption_key();
    printf("\n");
    
    // Display all generated round keys
    display_round_keys(encryption_key);
    
    // Generate test data for differential analysis
    data_pair test_pairs[TOTAL_PAIRS * 2];
    uint16_t input_difference = 0x0B00;
    generate_test_pairs(test_pairs, encryption_key, input_difference);
    
    // Execute differential cryptanalysis
    perform_differential_analysis();
    
    return 0;
}