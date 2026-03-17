//Manav Kumar - 202351078
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// sbox stuff
uint8_t sbox[16] = {0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7};
uint8_t inv_sbox[16] = {0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF, 0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5};

// perm thing
int perm[16] = {0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};

uint16_t keys[5];

// make round keys
void make_keys(uint32_t main_key) {
    for(int i=0; i<5; i++) {
        keys[i] = (main_key >> (16 - 4*(i+1))) & 0xFFFF;
    }
}

// apply sbox
uint16_t do_sbox(uint16_t x) {
    uint16_t out = 0;
    for(int i=0; i<4; i++) {
        uint8_t nib = (x >> (12-4*i)) & 0xF;
        out |= (sbox[nib] << (12-4*i));
    }
    return out;
}

// inverse sbox
uint16_t do_inv_sbox(uint16_t x) {
    uint16_t out = 0;
    for(int i=0; i<4; i++) {
        uint8_t nib = (x >> (12-4*i)) & 0xF;
        out |= (inv_sbox[nib] << (12-4*i));
    }
    return out;
}

// permute bits
uint16_t permute(uint16_t x) {
    uint16_t out = 0;
    for(int i=0; i<16; i++) {
        if(x & (1 << (15-i))) {
            out |= (1 << (15-perm[i]));
        }
    }
    return out;
}

// encrypt
uint16_t encrypt(uint16_t plain, uint32_t key) {
    make_keys(key);
    uint16_t state = plain;
    
    // rounds 1-3
    for(int r=0; r<3; r++) {
        state ^= keys[r];
        state = do_sbox(state);
        state = permute(state);
    }
    
    // round 4
    state ^= keys[3];
    state = do_sbox(state);
    state ^= keys[4];
    
    return state;
}

// partial decrypt for diff attack
void partial_decrypt(uint16_t cipher, uint8_t key_guess, uint8_t *out2, uint8_t *out4) {
    // get nibbles from ciphertext
    uint8_t c2 = (cipher >> 8) & 0xF;    // nibble 2
    uint8_t c4 = cipher & 0xF;           // nibble 4
    
    // get key parts
    uint8_t k2 = (key_guess >> 4) & 0xF; // for nibble 2
    uint8_t k4 = key_guess & 0xF;        // for nibble 4
    
    // undo last round
    *out2 = inv_sbox[c2 ^ k2];
    *out4 = inv_sbox[c4 ^ k4];
}

int main() {
    srand(time(NULL));
    
    // use fixed key for testing
    uint32_t main_key = 0x12345678;
    make_keys(main_key);
    
    printf("=== Diff Attack on SPN ===\n\n");
    
    // Print K5 in hex byte format
    printf("Actual K5 (16-bit): ");
    printf("%02X %02X\n", (keys[4] >> 8) & 0xFF, keys[4] & 0xFF);
    
    // Print target subkey in hex byte format
    uint8_t target_subkey = ((keys[4] >> 8) & 0xF0) | ((keys[4] >> 4) & 0xF);
    printf("Target subkey (K5[15:12]|K5[7:4]): %02X\n\n", target_subkey);
    
    // make 100 plaintext pairs with diff 0x0B00
    uint16_t pairs[100][2];
    uint16_t diff = 0x0B00;
    
    printf("Making 100 plaintext pairs with diff 0x%04X...\n", diff);
    for(int i=0; i<100; i++) {
        pairs[i][0] = rand() & 0xFFFF;
        pairs[i][1] = pairs[i][0] ^ diff;
    }
    
    // encrypt all pairs
    uint16_t cipher_pairs[100][2];
    for(int i=0; i<100; i++) {
        cipher_pairs[i][0] = encrypt(pairs[i][0], main_key);
        cipher_pairs[i][1] = encrypt(pairs[i][1], main_key);
    }
    
    // do the actual diff attack
    int count[256] = {0};
    
    printf("Doing diff attack...\n");
    
    // for each key guess (00 to FF in hex)
    for(int kg=0; kg<256; kg++) {
        int good_pairs = 0;
        
        // check all pairs
        for(int i=0; i<100; i++) {
            uint16_t c1 = cipher_pairs[i][0];
            uint16_t c2 = cipher_pairs[i][1];
            
            // get nibbles 1 and 3
            uint8_t c1_1 = (c1 >> 12) & 0xF;
            uint8_t c1_3 = (c1 >> 4) & 0xF;
            uint8_t c2_1 = (c2 >> 12) & 0xF;
            uint8_t c2_3 = (c2 >> 4) & 0xF;
            
            // check if nibbles 1 and 3 are same
            if(c1_1 == c2_1 && c1_3 == c2_3) {
                // partial decrypt nibbles 2 and 4
                uint8_t v1_2, v1_4, v2_2, v2_4;
                partial_decrypt(c1, kg, &v1_2, &v1_4);
                partial_decrypt(c2, kg, &v2_2, &v2_4);
                
                // check if diff is 0x6 for both
                if((v1_2 ^ v2_2) == 0x6 && (v1_4 ^ v2_4) == 0x6) {
                    good_pairs++;
                }
            }
        }
        
        count[kg] = good_pairs;
    }
    
    // find best key
    int max_count = 0;
    int best_key = 0;
    for(int i=0; i<256; i++) {
        if(count[i] > max_count) {
            max_count = count[i];
            best_key = i;
        }
    }
    
    // print results in hex byte format
    printf("\n=== Results ===\n");
    printf("Most likely key: %02X (count: %d)\n", best_key, max_count);
    printf("Actual target:   %02X\n", target_subkey);
    printf("Attack success: %s\n\n", (best_key == target_subkey) ? "YES" : "NO");
    
    // print full count table for all 256 keys in hex
    printf("Key Count Table (all 256 keys in hex):\n");
    printf("Key  Count | Key  Count | Key  Count | Key  Count\n");
    
    for(int i=0; i<256; i++) {
        printf("%02X   %3d   ", i, count[i]);
        if((i+1) % 4 == 0) printf("\n");
    }
    
    // show top candidates
    printf("\nTop candidates:\n");
    int sorted[256];
    for(int i=0; i<256; i++) sorted[i] = i;
    
    // bubble sort
    for(int i=0; i<255; i++) {
        for(int j=0; j<255-i; j++) {
            if(count[sorted[j]] < count[sorted[j+1]]) {
                int temp = sorted[j];
                sorted[j] = sorted[j+1];
                sorted[j+1] = temp;
            }
        }
    }
    
    // print top 10 in hex
    printf("Top 10 keys:\n");
    for(int i=0; i<10 && i<256; i++) {
        int k = sorted[i];
        printf("%02X: %d hits", k, count[k]);
        if(k == target_subkey) printf(" <- ACTUAL");
        if(k == best_key) printf(" <- GUESSED");
        printf("\n");
    }
    
    return 0;
}



// // // Consider RSA cryptosystem with p = 761, q = 769 and e = 941.
// // // Here public key = (n, e), private key = (p, q, d)
// // // Consider the message m = 600.
// // // Select the appropriate option.
// // // a. e is legitimate, d = 43141, ciphertext = 48006
// // // b. e is legitimate, d = 44141, ciphertext = 48006
// // // c. e is legitimate, d = 47141, ciphertext = 48006 
// // // d. e is not legitimate, thus none of these
// // // e. e is legitimate, d = 4741, ciphertext = 48006
// // // Your answer is correct.
// // // The correct answer is:
// // // e is legitimate, d = 47141, ciphertext = 48006
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 2/12
// // // 2/29/24, 5:39 PM Question 2
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // Z∗
// // // p
// // // with multiplication mod p operation.
// // // Consider the Diffie-Hellman key exchange on the Group Let p = 3319 and generator of the group g = 6.
// // // Alice's secret key = 1197, Bob's secret key = 62.
// // // Select the most appropriate option.
// // // a. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890 
// // // b. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1891
// // // c. Alice's public key = 1658, Bob's public key = 1582, Shared secret key = 1890
// // // d. Alice's public key = 1582, Bob's public key = 1758, Shared secret key = 1890
// // // e. none of these
// // // Your answer is correct.
// // // The correct answer is:
// // // Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 3/12
// // // 2/29/24, 5:39 PM Question 3
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // y2 x3 ×
// // // Consider the Elliptic curver E: defined over .
// // // = + 13x + 23
// // // Z29 Z29
// // // What is the addition of two points (16 , 21) and (9, 12)?
// // // a. (24, 6) 
// // // b. (7, 14)
// // // c. (8, 28)
// // // d. None of these
// // // e. (16, 21)
// // // Your answer is correct.
// // // The correct answer is:
// // // (24, 6)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 4/12
// // // 2/29/24, 5:39 PM Question 4
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // y2 x3 ×
// // // Consider the Elliptic curve E: defined over .
// // // = + 11x + 23
// // // Z43 Z43
// // // What is the addition of two points (11, 23) and (26, 30)?
// // // a. (7, 20)
// // // b. (31, 38)
// // // c. (38, 31)
// // // d. (41, 6) 
// // // e. (6, 41)
// // // Your answer is correct.
// // // The correct answer is:
// // // (41, 6)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 5/12
// // // 2/29/24, 5:39 PM Question 5
// // // Incorrect
// // // Mark 0.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // AES-MIXCOLUMN (234, 56, 118, 221,)
// // // a. (54, 221, 63, 202)
// // // b. (44, 221, 66, 202)
// // // c. (44, 220, 66, 202)
// // // d. none of these
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 6/12
// // // 2/29/24, 5:39 PM CS364 (LAB ) Test: Attempt review
// // // e. (44, 221, 66, 201) 
// // // Your answer is incorrect.
// // // The correct answer is:
// // // (44, 221, 66, 202)
// // // Question 6
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // Consider the Diffie-Hellman key exchange on the Group Z∗
// // // p
// // // with multiplication mod p operation.
// // // Let p = 2689 and generator of the group g = 19.
// // // Alice's secret key = 119, Bob's secret key = 62.
// // // Select the most appropriate option.
// // // a. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409 
// // // b. Alice's public key = 1630 , Bob's public key = 2563 , Common secret key = 2409
// // // c. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2309
// // // d. Alice's public key = 1631 , Bob's public key = 2573 , Common secret key = 2409
// // // e. none of these
// // // Your answer is correct.
// // // The correct answer is:
// // // Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 7/12
// // // 2/29/24, 5:39 PM Question 7
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // y2 x3 ×
// // // Consider the Elliptic curve E: defined over .
// // // = + 23x + 11
// // // Z173 Z173
// // // What is the addition of two points (28 ,109) and (88, 147)?
// // // a. (112, 92)
// // // b. none of these
// // // c. (8,19) 
// // // d. (133, 73)
// // // e. (138, 10)
// // // Your answer is correct.
// // // The correct answer is:
// // // (8,19)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 8/12
// // // 2/29/24, 5:39 PM Question 8
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // AES-INV-MIXCOLUMN (123, 202, 87, 77)
// // // a. (114, 54, 143, 96)
// // // b. (52, 215, 139, 72)
// // // c. none of these
// // // d. (157, 132, 225, 110)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 9/12
// // // 2/29/24, 5:39 PM CS364 (LAB ) Test: Attempt review
// // // e. (54, 69, 87, 143) 
// // // Your answer is correct.
// // // The correct answer is:
// // // (54, 69, 87, 143)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 10/12
// // // 2/29/24, 5:39 PM Question 9
// // // Incorrect
// // // Mark 0.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // Consider RSA cryptosystem with p = 691, q = 701 and e = 563.
// // // Here public key = (n, e), private key = (p,q,d)
// // // Consider the message m = 600.
// // // Select the appropriate option.
// // // a. e is legitimate, d = 62617, ciphertext = 315318 
// // // b. e is legitimate, d = 62727, ciphertext = 315318
// // // c. e is legitimate, d = 61627, ciphertext = 315318
// // // d. e is legitimate, d = 62627, ciphertext = 315318
// // // e. e is not legitimate, thus none of these
// // // Your answer is incorrect.
// // // The correct answer is:
// // // e is legitimate, d = 62627, ciphertext = 315318
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 11/12
// // // 2/29/24, 5:39 PM Question 10
// // // Correct
// // // Mark 1.00 out of
// // // 1.00
// // // CS364 (LAB ) Test: Attempt review
// // // AES-INV-MIXCOLUMN (123, 212, 88, 77) [inputs are in decimal]
// // // a. (175, 152, 227, 110) 
// // // b. (175, 15, 227, 110)
// // // c. none of these
// // // d. (75, 152, 227, 110)
// // // e. (175, 152, 27, 110)
// // // Your answer is correct.
// // // The correct answer is:
// // // (175, 152, 227, 110)

// // // MIXCOLUMN (32, 198, 201, 35) = ?
// // // when we work on .
// // // F2 x8 x4 x3 x2
// // // [x]/ < + + + + 1 >
// // // Input, output are in decimal.
// // // a. (251, 212, 10, 41) 
// // // b. (231, 18, 101, 55)
// // // c. none of these
// // // d. (253, 212, 12, 41)
// // // e. (211, 213, 17, 37)
// // // Your answer is incorrect.
// // // The correct answer is:
// // // (253, 212, 12, 41)
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 1/6
// // // 4/30/24, 1:46 PM Question 2
// // // Correct
// // // Mark 1.00 out of 1.00
// // // LAB test: Attempt review
// // // Consider a Playfair cipher with key = aedoqmw
// // // What is the correct ciphertext of the plaintext = iamd
// // // a. gdba 
// // // b. dgab
// // // c. hewe
// // // d. ehew
// // // e. none of these
// // // Your answer is correct.
// // // The correct answer is:
// // // gdba
// // // Question 3
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Let p = 2147483647. If a = 13 then the multiplicative inverse
// // // of a under mod p is =
// // // a. 1486719447
// // // b. 1486719448
// // // 
// // // c. none of these
// // // d. 1486619448
// // // e. 1486729448
// // // Your answer is correct.
// // // The correct answer is:
// // // 1486719448
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 2/6
// // // 4/30/24, 1:46 PM Question 4
// // // Incorrect
// // // Mark 0.00 out of 1.00
// // // LAB test: Attempt review
// // // MIXCOLUMN (32, 198, 201, 35) = ?
// // // when we work on .
// // // F2 x8 x6 x5 x4 x2
// // // [x]/ < + + + + + x + 1 >
// // // Input, output are in decimal.
// // // a. (151, 212, 102, 41)
// // // b. (151, 212, 102, 11)
// // // c. none of these
// // // d. (151, 202, 102, 41)
// // // e. (151, 102, 212, 41) 
// // // Your answer is incorrect.
// // // The correct answer is:
// // // (151, 212, 102, 41)
// // // Question 5
// // // Not answered
// // // Not graded
// // // Consider a modified Playfair cipher on
// // // { A, B, C, D,..., Z, \ , /, [ , ] } . Note that the set has 30 elements.
// // // Consider the key = AETIMPSB and select the encryption of
// // // plaintext = CRYPTO\N
// // // a. QDUDWBEV
// // // b. QDUDBWEV
// // // c. QDUDBWVE
// // // d. none of these
// // // e. QDDUBWEV
// // // Your answer is incorrect.
// // // The correct answers are:
// // // QDUDBWEV,
// // // none of these
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 3/6
// // // 4/30/24, 1:46 PM Question 6
// // // Incorrect
// // // Mark 0.00 out of 1.00
// // // LAB test: Attempt review
// // // Consider AES-Subbyte table Sub().
// // // We define a new S-box from Sub as follows:
// // // S(x) = Sub((2*x)+1), here a*x and y+b are done in
// // // F2 x8 x6 x5 x4 x2
// // // [x]/ < + + + + + x + 1 >
// // // .
// // // What is value of S(212)? Here input, output are in decimal.
// // // a. 113
// // // b. 29
// // // c. 92 
// // // d. 28
// // // e. none of these
// // // Your answer is incorrect.
// // // The correct answer is:
// // // 29
// // // Question 7
// // // Correct
// // // Mark 1.00 out of 1.00
// // // CAESAR-Encryption ( aeqwg ) = ?
// // // a. dthjz
// // // b. dhtzq
// // // c. dhtzj 
// // // d. none of these
// // // e. ahtzj
// // // Your answer is correct.
// // // The correct answer is:
// // // dhtzj
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 4/6
// // // 4/30/24, 1:46 PM Question 8
// // // Incorrect
// // // Mark 0.00 out of 1.00
// // // LAB test: Attempt review
// // // Consider Affine encryption algorithm.
// // // If the secret key is K = (11,5), the ciphertext of the
// // // plaintext = aeswq is = ?
// // // a. fxvnz
// // // b. none of these
// // // c. fxvny 
// // // d. fzvnx
// // // e. fxnvz
// // // Your answer is incorrect.
// // // The correct answer is:
// // // fxvnz
// // // Question 9
// // // Incorrect
// // // Mark 0.00 out of 1.00
// // // Consider AES-Subbyte table Sub().
// // // We define a new S-box from Sub as follows:
// // // S(x) = Sub((2*x)+1), here a*x and y+b are done in
// // // F2 x8 x4 x3
// // // [x]/ < + + + x + 1 >
// // // .
// // // What is value of S(126)? Here input, output are in decimal.
// // // a. 48
// // // b. 84
// // // c. 83
// // // d. 88 
// // // e. none of these
// // // Your answer is incorrect.
// // // The correct answer is:
// // // 84
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 5/6
// // // 4/30/24, 1:46 PM Question 10
// // // Incorrect
// // // Mark 0.00 out of 1.00
// // // LAB test: Attempt review
// // // Consider Shift cipher and find the encryption of
// // // the plaintext = aeqwg
// // // where key = 5
// // // a. fjvlb
// // // b. none of these
// // // d. fvjbl 
// // // c. fjvbl
// // // e. fjvbp
// // // Your answer is incorrect.
// // // The correct answer is:
// // // fjvbl
// // // ◄ Announcements
// // // Jump to...
// // // LAB -Assignment 1 ►
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 6/6
// // // 5/24/24, 4:50 PM Endterm Test: Attempt review
// // // Dashboard / Courses / Winter 2023-24 / B.Tech Semester 6 / CS364_2024 / General / Endterm Test
// // // Started on Tuesday, 30 April 2024, 9:50 AM
// // // State Finished
// // // Completed on Time taken Tuesday, 30 April 2024, 10:06 AM
// // // 16 mins 25 secs
// // // Grade 11.00 out of 11.00 (100%)
// // // Question 1
// // // Correct
// // // Mark 1.00 out of 1.00
// // // AES-MIXCOLUMN (234, 56, 118, 221) [Input/Output are in Decimal]
// // // a. (44, 221, 66, 202) 
// // // b. (44, 221, 66, 201)
// // // c. (44, 220, 66, 202)
// // // d. (54, 221, 63, 202)
// // // e. none of these
// // // Your answer is correct.
// // // Question 2
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Consider the Diffie-Hellman key exchange on the Group Z∗
// // // p
// // // Let p = 3319 and generator of the group g = 6.
// // // Alice's secret key = 1197, Bob's secret key = 62.
// // // Select the most appropriate option.
// // // with multiplication mod p operation.
// // // a. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890 
// // // b. Alice's public key = 1582, Bob's public key = 1758, Shared secret key = 1890
// // // c. none of these
// // // d. Alice's public key = 1658, Bob's public key = 1582, Shared secret key = 1890
// // // e. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1891
// // // Your answer is correct.
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 1/6
// // // 5/24/24, 4:50 PM Question 3
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Endterm Test: Attempt review
// // // Consider RSA cryptosystem with p = 691, q = 701 and e = 563.
// // // Here public key = (n, e), private key = (p,q,d)
// // // Consider the message m = 600.
// // // Select the appropriate option.
// // // a. e is not legitimate, thus none of these
// // // b. e is legitimate, d = 62727, ciphertext = 315318
// // // c. e is legitimate, d = 62627, ciphertext = 315318 
// // // d. e is legitimate, d = 61627, ciphertext = 315318
// // // e. e is legitimate, d = 62617, ciphertext = 315318
// // // Your answer is correct.
// // // Question 4
// // // Correct
// // // Mark 1.00 out of 1.00
// // // AES-INVERSE-MIXCOLUMN (123, 202, 87, 77) [Input/Output are in Decimal]
// // // a. (114, 54, 143, 96)
// // // b. (157, 132, 225, 110)
// // // c. none of these
// // // d. (52, 215, 139, 72)
// // // e. (54, 69, 87, 143) 
// // // Your answer is correct.
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 2/6
// // // 5/24/24, 4:50 PM Question 5
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Endterm Test: Attempt review
// // // Consider RSA cryptosystem with p = 761, q = 769 and e = 941.
// // // Here public key = (n, e), private key = (p, q, d)
// // // Consider the message m = 600.
// // // Select the appropriate option.
// // // a. e is not legitimate, thus none of these
// // // b. e is legitimate, d = 47141, ciphertext = 48006 
// // // c. e is legitimate, d = 4741, ciphertext = 48006
// // // d. e is legitimate, d = 44141, ciphertext = 48006
// // // e. e is legitimate, d = 43141, ciphertext = 48006
// // // Your answer is correct.
// // // Question 6
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Consider the Elliptic curve E: defined over .
// // // y2 x3 ×
// // // = + 11x + 23
// // // Z43 Z43
// // // What is the addition of two points (11, 23) and (26, 30)?
// // // a. (7, 20)
// // // b. (38, 31)
// // // c. (31, 38)
// // // d. (6, 41)
// // // e. (41, 6) 
// // // Your answer is correct.
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 3/6
// // // 5/24/24, 4:50 PM Question 7
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Endterm Test: Attempt review
// // // AES-INVERSE-MIXCOLUMN (123, 212, 88, 77) [Input/Output are in Decimal]
// // // a. (75, 152, 227, 110)
// // // b. (175, 152, 227, 110) 
// // // c. (175, 152, 27, 110)
// // // d. none of these
// // // e. (175, 15, 227, 110)
// // // Your answer is correct.
// // // Question 8
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Consider the Diffie-Hellman key exchange on the Group Z∗
// // // p
// // // with multiplication mod p operation.
// // // Let p = 2689 and generator of the group g = 19.
// // // Alice's secret key = 119, Bob's secret key = 62.
// // // Select the most appropriate option.
// // // a. Alice's public key = 1630 , Bob's public key = 2563 , Common secret key = 2409
// // // b. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2309
// // // c. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409 
// // // d. Alice's public key = 1631 , Bob's public key = 2573 , Common secret key = 2409
// // // e. none of these
// // // Your answer is correct.
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 4/6
// // // 5/24/24, 4:50 PM Question 9
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Endterm Test: Attempt review
// // // Consider the AES-128 key-scheduling algorithm.
// // // If K0, K1, ... , K10 denotes the 11 round keys corresponding to the
// // // secret key K (in hexadecimal),
// // // K = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// // // Then K1 (in hexadecimal) is
// // // a. c0 39 34 78 84 6c 52 0f 0c f5 f8 b4 c0 28 16 4b 
// // // b. none of these
// // // c. c1 84 21 af ed 10 c0 2a 45 fb 89 de 5d a3 52 a5
// // // d. d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe
// // // e. 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// // // Your answer is correct.
// // // Question 10
// // // Correct
// // // Mark 1.00 out of 1.00
// // // = + 23x + 11
// // // Consider the Elliptic curve E: defined over .
// // // y2 x3 ×
// // // Z173 Z173
// // // What is the addition of two points (28 ,109) and (88, 147)?
// // // a. (112, 92)
// // // b. (8,19) 
// // // c. (138, 10)
// // // d. (133, 73)
// // // e. none of these
// // // Your answer is correct.
// // // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 5/6
// // // 5/24/24, 4:50 PM Question 11
// // // Correct
// // // Mark 1.00 out of 1.00
// // // Endterm Test: Attempt review
// // // Consider the Elliptic curve E: defined over .
// // // y2 x3 ×
// // // = + 13x + 23
// // // Z29 Z29
// // // What is the addition of two points (16 , 21) and (9, 12)?
// // // a. (24, 6) 
// // // b. (16, 21)
// // // c. (7, 14)
// // // d. None of these
// // // e. (8, 28)
// // // Your answer is correct.




// // Let n be a product of large primes i.e., n = p*q. We know that finding p, q from n is a computationally hard
// // problem.
// // If I give you n along with ϕ(n)
// // then will you be able to find p, q in polynomial time?
// // a. Yes 
// // b. No
// // Your answer is correct.
// // The correct answer is:
// // Yes
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 1/17
// // 2/29/24, 5:39 PM Question 2
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Let g : {0
// // ,1 → {0
// // ,1
// // }256 }256
// // be any preimage resistant function.
// // Define f : {0
// // ,1 → {0
// // ,1
// // }512 }512
// // by using the following rule:
// // x0 x511 1512 x0 x1 x255
// // f( ,…, ) = if = = ⋯ = = 1
// // x0 x511 1256 x256 x511
// // f( ,…, ) = ||g( ,…, ) otherwise
// // Here 1d
// // denotes a d
// // -bits string whose all bits are one. Which of the following statement is true?
// // 
// // a. f is preimage resistant function
// // b. f is not preimage resistant function
// // Your answer is correct.
// // The correct answer is:
// // f is preimage resistant function
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 2/17
// // 2/29/24, 5:39 PM Question 3
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Let H be a collision resistant hash function. Define a new hash function H1 based on H in the following way.
// // ≠
// // H1(X) = H(X) if X X0, H1(X) = H(X1) if X = X0 where X0 and X1 are not equal. Is H1 collision resistant?
// // a. Yes
// // b. No
// // 
// // Your answer is correct.
// // The correct answer is:
// // No
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 3/17
// // 2/29/24, 5:39 PM Question 4
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // x5 x4 x2
// // A 5-bit LFSR is constructed using the connection polynomial .
// // f(x) = + + + x+ 1
// // The period of this LFSR will be
// // a. 15
// // b. 30
// // c. None of these
// // d. 28
// // e. 31 
// // Your answer is correct.
// // The correct answer is:
// // 31
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 4/17
// // 2/29/24, 5:39 PM Question 5
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Let n=pq where p,q are primes. Consider e such that [here gcd(e,ϕ(n)) = 1 ϕ
// // is the Euler's totient function].
// // xe
// // f(x) = mod n
// // The function defined by is
// // a. a permutation on
// // Z∗
// // n
// // 
// // b. not a permutation on
// // Z∗
// // n
// // Your answer is correct.
// // The correct answer is:
// // a permutation on Z∗
// // n
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 5/17
// // 2/29/24, 5:39 PM Question 6
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // Class Test: Attempt review
// // Let Fk Fk−1 Pk Fk−1 Enc
// // = ⊕ Enc( , )
// // be an iterated hash function where ,
// // and each is of -bit.
// // Fk Pk 64
// // is the DES encryption algorithm
// // F0
// // 64 Pk k
// // The initial is a -bit public data, is the -th message block.
// // Which of the following statement is correct?
// // a. The above iterated hash function is not a collision resistant hash function.
// // b. The above iterated hash function is a collision resistant hash function.
// // 
// // Your answer is incorrect.
// // The correct answer is:
// // The above iterated hash function is not a collision resistant hash function.
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 6/17
// // 2/29/24, 5:39 PM Question 7
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // If g is a generator of the group Z∗ m where Z∗ m
// // = {x | gcd(x,m) = 1}
// // (m is not a prime)
// // then what is the order of g?
// // a. none of these
// // b.
// // m− 1
// // c.
// // (m− 1)(m− 2)
// // d.
// // 
// // ϕ(m)
// // Your answer is correct.
// // The correct answer is:
// // ϕ(m)
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 7/17
// // 2/29/24, 5:39 PM Question 8
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Consider the following system of equations.
// // x≡ 3 mod 83
// // x≡ 5 mod 79
// // Does the above system have solution?
// // a. No
// // b. Yes 
// // Your answer is correct.
// // The correct answer is:
// // Yes
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 8/17
// // 2/29/24, 5:39 PM Question 9
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // If AES-Mixcolumn(23, 67, 45, 89) = (x,y,z,w) then [here input and output are in integer]
// // a. none of these
// // b. y = 159
// // c. y = 229
// // d. y = 121
// // 
// // e. y = 191
// // Your answer is correct.
// // The correct answer is:
// // y = 191 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 9/17
// // 2/29/24, 5:39 PM Question 10
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // If n = pq, where p, q are large primes. We state the following problems P1 and P2:
// // P1: Find p, q from n.
// // P2: Compute ϕ(n)
// // without knowing p, q.
// // Which of the following statement is true?
// // a. Solving P2 is harder than P1
// // b. Problems P1 and P2 are equivalent 
// // c. Solving P1 is harder than P2
// // Your answer is correct.
// // The correct answer is:
// // Problems P1 and P2 are equivalent
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 10/17
// // 2/29/24, 5:39 PM Question 11
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Let as h : →
// // Z2512 Z2256
// // be a hash function defined
// // h(x) = (155 + 201 + 2 + 101x+ 1) mod
// // x4 x3 x2 2256 h
// // . Is second preimage resistant?
// // a. No 
// // b. Yes
// // Your answer is correct.
// // The correct answer is:
// // No
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 11/17
// // 2/29/24, 5:39 PM Question 12
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // For each key DES is basically a permutation i.e., we can have 256
// // such permutations.
// // With all these permutations consider the set G. Now G with the operation composition of permutation
// // a. is closed
// // b. is not closed
// // 
// // Your answer is correct.
// // The correct answer is:
// // is not closed
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 12/17
// // 2/29/24, 5:39 PM Question 13
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // Class Test: Attempt review
// // Consider the AES-128 encryption algorithm. AES-128 encryption algorithm takes an 128-bit key and an 128-bit
// // message block and generates 128-bit ciphertext block (AES-128(M,K)=C)
// // i.e., AES-128: .
// // {0
// // ,1 × {0
// // }128 }128 }128
// // ,1 → {0
// // ,1
// // Define the compression function by
// // h : {0
// // ,1 → {0
// // ,1
// // }256 }128
// // m1 m2 m1 m2
// // h( || ) = AES-128( , )
// // .
// // Which of the following statement is true
// // a. h is not collision resistant.
// // b. h is collision resistant.
// // 
// // Your answer is incorrect.
// // The correct answer is:
// // h is not collision resistant.
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 13/17
// // 2/29/24, 5:39 PM Question 14
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Consider a large prime number and the group
// // Zp
// // p ( ,+ mod p)
// // (here Zp
// // = {0
// // ,1,…,p− 1}
// // ). Which of the following statement is true
// // a. Discrete Log problem is computationally hard on this group.
// // b. Discrete Log problem is not computationally hard on this group.
// // 
// // Your answer is correct.
// // The correct answer is:
// // Discrete Log problem is not computationally hard on this group.
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 14/17
// // 2/29/24, 5:39 PM Question 15
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // Consider the prime number p=181 and the group Z∗
// // p
// // with multiplication modulo p operation.
// // Let g=2 be a generator of the group. Alice and Bob now would like to establish a common secret key using
// // Diffie-Hellman key exchange protocol on the above mentioned group. The secret key of Alice and Bob
// // are 97 and 82 respectively. Which of the following statement is correct.
// // a. Alice's public key = 53, Bob's public key = 111, Common secret key = 60} 
// // b. Alice's public key = 51, Bob's public key = 110, Common secret key = 65
// // c. Alice' public key = 43, Bob's public key = 109, Common secret key = 64
// // d. None of these
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 53, Bob's public key = 111, Common secret key = 60}
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 15/17
// // 2/29/24, 5:39 PM Question 16
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Class Test: Attempt review
// // If AES-Mixcolumn(23, 67, 89, 45) = (x,y,z,w) then [here input and output are in integer]
// // a. w = 87
// // b. w = 121 
// // c. none of these
// // d. w = 159
// // e. w = 145
// // Your answer is correct.
// // The correct answer is:
// // w = 121
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 16/17
// // 2/29/24, 5:39 PM ◄ Announcements Jump to...
// // Class Test: Attempt review
// // 
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108114&cmid=3586 17/17
// // Dashboard / Courses / Winter 2023-24 / B.Tech Semester 6 / CS304_2024 / General / Classtest
// // Started on Friday, 1 March 2024, 11:03 AM
// // State Finished
// // Completed on Time taken Friday, 1 March 2024, 11:23 AM
// // 19 mins 55 secs
// // Grade 3.50 out of 6.00 (58%)
// // Question 1
// // Correct
// // Mark 0.50 out of
// // 0.50
// // Consider AES-256 bit encryption algorithm and a 512 bit key K=K1||K2 where K1 and K2 are of 256 bit.
// // The encryption algorithm C=AES-256(AES-256(M,K1),K2) provides
// // a. 512-bit security
// // b. 256-bit security
// // Your answer is correct.
// // The correct answer is:
// // 256-bit security
// // 
// // 
// // Question 2
// // Correct
// // Mark 1.00 out of
// // 1.00
// // If AES-Mixcolumn(23, 67, 89, 45) = (x,y,z,w) then w =
// // [here input and output are in integer]
// // a. none of these
// // b. 121
// // 
// // c. 87
// // d. 159
// // e. 145
// // Your answer is correct.
// // The correct answer is:
// // 121
// // Question 3
// // Correct
// // Mark 1.00 out of
// // 1.00
// // If AES-Mixcolumn(23, 67, 45, 89) = (x,y,z,w) then y =
// // [here input and output are in integer]
// // a. 229
// // b. 121
// // 
// // c. 191
// // d. 159
// // Your answer is correct.
// // The correct answer is:
// // 191 
// // Question 4
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // Consider one-bit encryption . If and
// // C = P ⊕ K Pr[K = 0] = 0.5 Pr[P = 1] = 0.3
// // then is
// // Pr[P = 0|C = 1]
// // a. 0.5
// // b. 0.7
// // c. 0.4 
// // d. 0.3
// // e. none of these
// // Your answer is incorrect.
// // The correct answer is:
// // 0.7
// // Question 5
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // 3 2
// // 8 4 3
// // Which is the correct multiplicative inverse of the polynomial g(x)=x +x in Z [x]/x +x +x +x+1.
// // 2
// // 3
// // a. x +x+1
// // b. x +x +x
// // 7 5 4
// // 
// // 6 3
// // c. x +x +x
// // Your answer is incorrect.
// // The correct answer is:
// // 7 5 4
// // x +x +x
// // 
// // Question 6
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // 
// // x4 x3
// // + + x
// // Your answer is incorrect.
// // The correct answer is:
// // x4 x3 x2
// // + + + x + 1
// // Question 7
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // Which is the correct multiplicative inverse of the polynomial Z2 x5 x4 x2
// // [x]/ + + + x + 1
// // .
// // g(x) = +
// // x3 x2
// // in
// // a.
// // x4 x2
// // + + x + 1
// // b.
// // x4 x3 x2
// // + + + x + 1
// // c.
// // We define a new encryption algorithm TEnc using AES-128 encryption
// // technique.
// // TEnc : where
// // {0
// // ,1 × {0
// // ,1 → {0
// // ,1
// // }384 }128 }128
// // ⊕ ⊕
// // C = TEnc(K||K1||K2, M) = K2 AES-128-Enc(K, K1 M).
// // Here K, K1, K2 each is of 128 bit. What will be the decryption algorithm
// // (TDec) corresponding to TEnc.
// // a. M = TDec(K||K1||K2, C) = K ⊕ ⊕
// // AES-128-Dec(K1, K2 C)
// // b.
// // ⊕ ⊕
// // M = TDec(K||K1||K2, C) = K1 AES-128-Dec(K, K2 C)
// // c. None of these
// // d. M = TDec(K||K1||K2, C) = K2 AES-128-Dec(K, K1 C) 
// // ⊕ ⊕
// // Your answer is incorrect.
// // The correct answer is:
// // ⊕ ⊕
// // M = TDec(K||K1||K2, C) = K1 AES-128-Dec(K, K2 C)
// // 
// // Question 8
// // Correct
// // Mark 0.50 out of
// // 0.50
// // What is the period of the 5-bit LFSR whose connection polynomial is
// // x5 x4 x2
// // + + + x + 1
// // a. 32
// // b. 31 
// // c. none of these
// // d. 15
// // e. 16
// // Your answer is correct.
// // The correct answer is:
// // 31
// // Question 9
// // Incorrect
// // Mark 0.00 out of
// // 0.50
// // 6 4
// // 6 4
// // Select the correct answer where S : {0,1} → {0,1} and S :{0,1} → {0,1} are the first two
// // 1
// // 2
// // defined S-boxes for the round function of DES. (For the description of these S-boxes please
// // see Handbook of Applied Cryptography book.)
// // a. S (59) = 1, S2(23) = 10.
// // 1
// // b. S (59) = 4, S (23) = 8
// // 1 2
// // c. S (59) = 0, S (23) = 10.
// // 1 2
// // d. S (59) = 0, S (23) = 14.
// // 1 2
// // 
// // Your answer is incorrect.
// // The correct answer is:
// // S (59) = 0, S (23) = 10.
// // 1 2
// // 
// // Question 10
// // Correct
// // Mark 0.50 out of
// // 0.50
// // A sequence of plaintext blocks x1,...,xn are encrypted by
// // using AES-128 in CBC mode. The corresponding ciphertext blocks
// // are y1,...,yn. During transmission y1 is transmitted incorrectly
// // (i.e., some 1's are changed to 0's and vice verse).
// // The number of plaintext blocks that will be decrypted incorrectly is
// // a. 2 
// // b. n
// // c. 3
// // d. none of these
// // e. 1
// // Your answer is correct.
// // The correct answer is:
// // 2
// // ◄ Announcements Jump to...
// // 
// // Dashboard / My courses /
// // CS304 /
// // Topic 1 /
// // Midterm
// // Started on Thursday, 10 March 2022, 2:34 PM
// // State Finished
// // Completed on Time taken Thursday, 10 March 2022, 3:53 PM
// // 1 hour 18 mins
// // Grade 20.00 out of 40.00 (50%)
// // Question 1
// // Incorrect
// // Mark 0.00 out of 1.00
// // The expansion function of DES is
// // a. not invertible
// // b. invertible
// // Your answer is incorrect.
// // The correct answer is:
// // invertible
// // 
// // Question 2
// // Incorrect
// // Mark 0.00 out of 1.00
// // Assume that in a classroom there are 250 students. Form a group by taking x many
// // students randomly from the classroom. For which value of x there will be atleast
// // two students with same date of birth with probability 0.9.
// // a. none of these 
// // b. 35
// // c. 41
// // d. 30
// // Your answer is incorrect.
// // The correct answer is:
// // 41
// // Question 3
// // Incorrect
// // Mark 0.00 out of 1.00
// // Expanded key size of AES-256 is
// // a. 44 words
// // b. 56 words
// // c. 48 words
// // d. 60 words
// // e. none of these
// // Your answer is incorrect.
// // The correct answer is:
// // 60 words
// // 
// // Question 4
// // Correct
// // Mark 1.00 out of 1.00
// // If AES-Mixcolumn(23, 67, 45, 89) = (x,y,z,w) then y =
// // [here input and output are in integer]
// // a. 191
// // b. 159
// // c. 229
// // d. 121
// // Your answer is correct.
// // The correct answer is:
// // 191
// // 
// // Question 5
// // Correct
// // Mark 1.00 out of 1.00
// // What are the correct values of x,y such that 23x+43y=gcd(23,43)?
// // a. x=13,y=7
// // b. x=15,y=-8
// // c. x=25,y=-18
// // d. none of these
// // e. x=-24,y=16
// // Your answer is correct.
// // The correct answer is:
// // x=15,y=-8
// // 
// // Question 6
// // Incorrect
// // Mark 0.00 out of 1.00
// // P C K
// // Let , , be the plaintext space, ciphertext space and key space respectively.
// // E
// // Consider an encryption algorithm with the following conditions:
// // 1.
// // |P| = |C| = |K|
// // 2. every key is equiprobable
// // p ∈ P c ∈ C k E(p,k) = c
// // 3. for every , there is an unique key such that ,
// // Select the most appropriate option
// // a. provides perfect secrecy
// // E
// // b. E |K| > |P|
// // will provide perfect secrecy if
// // c. E
// // can not provide perfect secrecy as it differs from OTP
// // Your answer is incorrect.
// // The correct answer is:
// // E provides perfect secrecy
// // 
// // Question 7
// // Incorrect
// // Mark 0.00 out of 1.00
// // What is meant by the security of an Encryption Scheme?
// // a. An attacker who gets hold of a ciphertext should not be able to get any function of the bits of the plaintext
// // b. An attacker who gets hold of a ciphertext should not be able to get any bit of the plaintext
// // c. An attacker who gets hold of a ciphertext should not be able to know the plaintext
// // d. An attacker who gets hold of a ciphertext should not be able to get the secret key used for the encryption
// // 
// // Your answer is incorrect.
// // The correct answer is:
// // An attacker who gets hold of a ciphertext should not be able to get any bit of the plaintext
// // Question 8
// // Incorrect
// // Mark 0.00 out of 1.00
// // The number of valid keys in the Affine Cipher over \mathbb{Z}_{46} is
// // a. none of these 
// // b. 1012
// // c. 46
// // d. 2116
// // Your answer is incorrect.
// // The correct answer is:
// // 1012
// // Question 9
// // Incorrect
// // Mark 0.00 out of 1.00
// // Let F denotes the AES-128 bit encryption algorithm.
// // Define a function f:\{0,1\}^{128}\rightarrow \{0,1\}^{128} as
// // f(x)=F(x,K)\oplus x, here x,K are of 128-bits and K is a fixed secret key.
// // Which of the following statement is correct?
// // a. f is not an one-way function
// // b. f is an one-way function
// // Your answer is incorrect.
// // The correct answer is:
// // f is an one-way function
// // 
// // Question 10
// // Correct
// // Mark 1.00 out of 1.00
// // Which is the multiplicative inverse of (x^3+x^2+1) in
// // (\mathbb{F}_
// // 2[x]/<x^8+x^4+x^3+x+1>,+,
// // *). Here + and * are
// // the polynomial addition and polynomial multiplication under
// // modulo x^8+x^4+x^3+x+1.
// // a. x^7+x^6+x+1
// // b. none of these
// // c. x^7+x^6+x^2+1
// // d.
// // x^7 + x^6 + x^3 + x^2
// // e. x^7 + x^6 + x^5 + 1
// // Your answer is correct.
// // The correct answer is:
// // x^7 + x^6 + x^5 + 1
// // 
// // Question 11
// // Correct
// // Mark 1.00 out of 1.00
// // For a fixed key any symmetric key encryption algorithm should
// // a. not necessary to be surjective
// // b. none of these
// // c. not necessary to be injective
// // d. be surjective function
// // e. be injective function
// // Your answer is correct.
// // The correct answer is:
// // be injective function
// // 
// // Question 12
// // Incorrect
// // Mark 0.00 out of 1.00
// // Select the correct answer where S
// // _
// // 1:\{0,1\}^6\rightarrow\{0,1\}^4
// // and S
// // _
// // 2:\{0,1\}^6\rightarrow\{0,1\}^4 are the pre-defined S-boxes
// // for the round function of DES.
// // a. S
// // _
// // 1(55)=14, S
// // _
// // 2(43)=15
// // b. S
// // _
// // 1(55)=6, S
// // _
// // 2(43)=7
// // c. S
// // _
// // 1(55)=15, S
// // _
// // 2(43)=14
// // d. S
// // _
// // 1(55)=7, S
// // _
// // 2(43)=6
// // e. none of these 
// // Your answer is incorrect.
// // The correct answer is:
// // S
// // _
// // 1(55)=14, S
// // _
// // 2(43)=15
// // Question 13
// // Correct
// // Mark 1.00 out of 1.00
// // Let n=p\times q where p,q are two large primes.
// // Here n is known to everyone and p,q are hidden.
// // Consider the hash function h(x)=x^2\mod n.
// // a. h is not an one-way function
// // b. h is an one-way function
// // Your answer is correct.
// // The correct answer is:
// // h is an one-way function
// // 
// // Question 14
// // Incorrect
// // Mark 0.00 out of 1.00
// // If AES-Mixcolumn(23, 67, 89, 45) = (x,y,z,w) then w =
// // [here input and output are in integer]
// // a. 121
// // b. 87
// // c. 159
// // d. 145
// // e. none of these
// // Your answer is incorrect.
// // The correct answer is:
// // 121
// // 
// // Question 15
// // Correct
// // Mark 1.00 out of 1.00
// // Let h:\mathbb{Z}_{2^{512}}\rightarrow \mathbb{Z}_{2^{256}} be a hash function
// // defined as h(x)=(155x^4+201x^3+2x^2+101x+1)\mod 2^{256}.
// // Is h second preimage resistant?
// // a. yes
// // b. no
// // Your answer is correct.
// // The correct answer is:
// // no
// // Question 16
// // Correct
// // Mark 1.00 out of 1.00
// // Consider AES-128 in CFB mode of operation. One message of length 1024 bits
// // has been encrypted using AES-128 in CFB mode of operation.
// // Now to decrypt the ciphertext which of the following process needs to be followed
// // a. encryption of AES-128 needs to fit in CFB mode
// // b. decryption of AES-128 needs to fit in CFB mode
// // Your answer is correct.
// // The correct answer is:
// // encryption of AES-128 needs to fit in CFB mode
// // 
// // 
// // Question 17
// // Correct
// // Mark 1.00 out of 1.00
// // Consider playfair cipher with the key KEYWORD. Which is the correct
// // ciphertext of the plaintext COMMUNICATION when the plaintext is
// // encrypted using playfair cipher with the mentioned key.
// // a. none of these
// // b. LCQTNTQGBRXFES
// // c. LCQTNTQGRBXFES
// // d. LCQTNQTGRBXFES
// // e. LCQTNTQRGBXFES
// // Your answer is correct.
// // The correct answer is:
// // LCQTNTQGRBXFES
// // Question 18
// // Correct
// // Mark 1.00 out of 1.00
// // Decryption of CBC mode of operation can be implemented in parallel
// // a. no
// // b. yes
// // Your answer is correct.
// // The correct answer is:
// // yes
// // 
// // 
// // Question 19
// // Incorrect
// // Mark 0.00 out of 1.00
// // Which is the multiplicative inverse of (x^4+x^3+x+1) in (\mathbb{F}_
// // 2[x]/<x^8+x^4+x^3+x+1>,+,
// // *).
// // Here + and * are the polynomial addition and polynomial multiplication under modulo x^8+x^4+x^3+x+1.
// // a.
// // x^7 + x^6 + x^3 + x^2
// // b.
// // x^7 + x^6 + x^5 + 1
// // c. x^7 + x^6 + x^2 + x + 1
// // d.
// // x^7 + x^6 + x^3 + x^2+1
// // e. none of these 
// // Your answer is incorrect.
// // The correct answer is:
// // x^7 + x^6 + x^3 + x^2
// // Question 20
// // Incorrect
// // Mark 0.00 out of 1.00
// // SUBBYTES(6A) =
// // a. none of these 
// // b. 34
// // c. 20
// // d. 24
// // e. 02
// // Your answer is incorrect.
// // The correct answer is:
// // 02
// // Question 21
// // Incorrect
// // Mark 0.00 out of 1.00
// // How many distinct predefined functions are used in SHA-1
// // 
// // a. none of these
// // b. 4
// // c. 3
// // d. 80
// // Your answer is incorrect.
// // The correct answer is:
// // 3
// // Question 22
// // Incorrect
// // Mark 0.00 out of 1.00
// // Let F
// // k=F
// // _
// // _{k-1}\oplus Enc(P
// // _
// // k,F
// // _{k-1}) be an iterated hash function where AES-128 encryption algorithm and F
// // _
// // k, P
// // k each is of 128-bit.
// // _
// // Enc is the
// // The initial F
// // 0 is a 128-bit public data, P
// // _
// // k is
// // _
// // the k-th message block.
// // Which of the following statement is correct?
// // a. The above iterated hash function is a collision resistant hash function
// // b. The above iterated hash function is not a collision resistant hash function
// // Your answer is incorrect.
// // The correct answer is:
// // The above iterated hash function is a collision resistant hash function
// // 
// // Question 23
// // Correct
// // Mark 1.00 out of 1.00
// // Consider Affine cipher with the key K=(11, 16). Which is the correct ciphertext
// // of the plaintext MIDSEM when the plaintext is encrypted using Affine cipher
// // with the mentioned key.
// // a. SAXGIS
// // b. SAGXIS
// // c. SAXIGS
// // d. none of these
// // e. SAXGSI
// // Your answer is correct.
// // The correct answer is:
// // SAXGIS
// // 
// // Question 24
// // Incorrect
// // Mark 0.00 out of 1.00
// // Which of the following statement is correct?
// // a. if encryption function is oneway then decryption is not possible
// // b. encryption function is oneway if the private key is unknown
// // c. only hash functions are oneway functions
// // Your answer is incorrect.
// // The correct answer is:
// // encryption function is oneway if the private key is unknown
// // 
// // Question 25
// // Correct
// // Mark 1.00 out of 1.00
// // Consider playfair cipher with the key MIDSEM. Which is the correct
// // ciphertext of the plaintext VADODARA when the plaintext is
// // encrypted using playfair cipher with the mentioned key.
// // a. MHELMCPC
// // b. MHEMLCPC
// // c. none of these
// // d. MHLEMCPC
// // e. MHELCMPC
// // Your answer is correct.
// // The correct answer is:
// // MHELMCPC
// // 
// // Question 26
// // Correct
// // Mark 1.00 out of 1.00
// // Let h:\{0,1\}^*\rightarrow \{0,1\}^n be a preimage resistant and collision resistant
// // hash function. Define a new hash function h':\{0,1\}^*\rightarrow \{0,1\}^{n+1}
// // by using following rule h'(x)=0||x if x\in\{0,1\}^n,
// // otherwise h'(x)=1||h(x). Which of the following statement is true.
// // a. h' is neither preimage resistant nor collision resistant
// // b. h' is a preimage resistant as well as collision resistant
// // c. h' is not a preimage resistant but collision resistant
// // Your answer is correct.
// // The correct answer is:
// // h' is not a preimage resistant but collision resistant
// // 
// // Question 27
// // Correct
// // Mark 1.00 out of 1.00
// // If all the 16 round keys of DES are identical then
// // a. only the last round and first round of DES will be identical
// // b. DES encryption and decryption functions will not be identical due to the IP
// // c. DES encryption and decryption functions will be exactly equal
// // d. none of these
// // Your answer is correct.
// // The correct answer is:
// // DES encryption and decryption functions will be exactly equal
// // 
// // Question 28
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider AES-128 in OFB mode of operation. One message M of length 1024 bits
// // has been encrypted using AES-128 in OFB mode of operation. During transmission 256-th bit
// // and 512-th bit of the ciphertext are altered. Now the receiver performs the
// // decryption on the received ciphertext and obtained the decrypted text M'
// // .
// // Which of the following statement is true?
// // a. M and M' will differ from 256-th bit to 512-th bit
// // b. M and M' will differ at 256-th bit to 1024-th bit
// // c. none of these
// // d. M and M' will differ at 256-th bit and 512-th bit
// // Your answer is incorrect.
// // The correct answer is:
// // M and M' will differ at 256-th bit and 512-th bit
// // 
// // Question 29
// // Correct
// // Mark 1.00 out of 1.00
// // S-boxes in DES map
// // a. 4 bits to 6 bits
// // b. 2 bits to 4 bits
// // c. 4 bits to 4 bits
// // d. 6 bits to 4 bits
// // e. none of these
// // Your answer is correct.
// // The correct answer is:
// // 6 bits to 4 bits
// // 
// // Question 30
// // Correct
// // Mark 1.00 out of 1.00
// // Consider Affine cipher with the key K=(9, 19). Which is the correct
// // ciphertext of the plaintext INDIA when the plaintext is encrypted
// // using Affine cipher with the mentioned key.
// // a. NGUNM
// // b. none of these
// // c. NGTNU
// // d. NUGNT
// // e. NGUNT
// // Your answer is correct.
// // The correct answer is:
// // NGUNT
// // 
// // Question 31
// // Correct
// // Mark 1.00 out of 1.00
// // Let h:\mathbb{Z}_{512}\times Z
// // _{512}\rightarrow \mathbb{Z}_{512} be a hash
// // function defined as h(x,y)=(ax+by)\mod 512, a,b\in\mathbb{Z}_{512}.
// // Which of the following is correct?
// // a. h is an ideal hash function
// // b. h is not an ideal hash function
// // Your answer is correct.
// // The correct answer is:
// // h is not an ideal hash function
// // 
// // Question 32
// // Incorrect
// // Mark 0.00 out of 1.00
// // A sequence of plaintext blocks x1,...,xn are encrypted by
// // using AES-128 in CBC mode. The corresponding ciphertext blocks
// // are y1,...,yn. During transmission y1 is transmitted incorrectly
// // (i.e., some 1's are changed to 0's and vice verse).
// // The number of plaintext blocks that will be decrypted incorrectly is
// // a. none of these
// // b. 1
// // c. 2
// // d. 3
// // e. n
// // Your answer is incorrect.
// // The correct answer is:
// // 2
// // 
// // Question 33
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider one-bit encryption C=P\oplus K. If Pr[K=0]=0.5 and Pr[P=1]=0.3
// // then Pr[P=0|C=1] is
// // a. 0.7
// // b. 0.5
// // c. none of these
// // d. 0.4
// // e. 0.3
// // Your answer is incorrect.
// // The correct answer is:
// // 0.7
// // 
// // Question 34
// // Incorrect
// // Mark 0.00 out of 1.00
// // Select the most appropriate one. Hash function has the following property
// // a. Preimage finding is hard
// // b. Finding preimage, collision, second preimage all are hard
// // c. Finding preimage or collision or second preimage may not be hard
// // d. Second preimage finding is hard
// // e. Collision finding is hard
// // Your answer is incorrect.
// // The correct answer is:
// // Finding preimage or collision or second preimage may not be hard
// // 
// // Question 35
// // Correct
// // Mark 1.00 out of 1.00
// // Let C
// // _
// // 1=DES(M,K) and C
// // _
// // 2=DES(\bar{M},K). Which of the following relation is true?
// // a. none of these
// // b. C
// // _
// // 1=\bar{C
// // _
// // 2}
// // c. C
// // 1=C
// // 2
// // _
// // _
// // Your answer is correct.
// // The correct answer is:
// // none of these
// // Question 36
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider AES-128 in OFB mode of operation. One message of length 1024 bits
// // has been encrypted using AES-128 in OFB mode of operation. Now to decrypt the
// // ciphertext which of the following process needs to be followed
// // a. decryption of AES-128 needs to fit in OFB mode
// // b. encryption of AES-128 needs to fit in OFB mode
// // Your answer is incorrect.
// // The correct answer is:
// // encryption of AES-128 needs to fit in OFB mode
// // 
// // 
// // Question 37
// // Correct
// // Mark 1.00 out of 1.00
// // Consider one round of Feistel network with the block size 64-bit and
// // the secret key K of size 32-bit. The round function is defined by
// // f(R
// // _
// // 0,K)=S(R
// // _
// // 0\oplus K) where S(X)=(X+1)\mod 2^{32}.
// // Find the ciphertext for the plaintext = 1 and key K = 1.
// // a. 2147483648
// // b. 4294967297
// // c. none of these
// // d. 2147483649
// // e. 4294967296
// // Your answer is correct.
// // The correct answer is:
// // 4294967297
// // 
// // Question 38
// // Correct
// // Mark 1.00 out of 1.00
// // Assume that in a classroom there are 220 students. Form a group by
// // taking x many students randomly from the classroom. For which value
// // of x there will be atleast two students with same date of birth
// // with probability 0.7.
// // a. 30
// // b. 35
// // c. none of these
// // d. 28
// // Your answer is correct.
// // The correct answer is:
// // 30
// // Question 39
// // Correct
// // Mark 1.00 out of 1.00
// // Encryption of CBC mode of operation can be implemented in parallel
// // a. no
// // b. yes
// // Your answer is correct.
// // The correct answer is:
// // no
// // 
// // 
// // Question 40
// // Incorrect
// // Mark 0.00 out of 1.00
// // For each key DES is basically a permutation i.e., we can have 2^{56} such
// // permutations. With all these permutations consider the set G.
// // Now G with the operation composition of permutations
// // a. is not closed
// // b. is closed
// // 
// // Your answer is incorrect.
// // The correct answer is:
// // is not closed
// // ◄ Announcements
// // Jump to...
// // Endterm ►
// // Dashboard / My courses /
// // CS304 /
// // Topic 1 /
// // Endterm
// // Started on Thursday, 12 May 2022, 2:05 PM
// // State Finished
// // Completed on Time taken Thursday, 12 May 2022, 3:25 PM
// // 1 hour 20 mins
// // Grade 20.00 out of 40.00 (50%)
// // Question 1
// // Correct
// // Mark 1.00 out of 1.00
// // Let n = 53 * 73 and the encryption key of RSA be e = 679.
// // For the message M = 1234 which of the following statement is true.
// // a. none of these
// // b. the decryption key d = 2160, ciphertext C = 3693
// // c. the decryption key d = 787, ciphertext C = 760
// // d. the decryption key d = 2167, ciphertext C = 3693
// // Your answer is correct.
// // The correct answer is:
// // the decryption key d = 2167, ciphertext C = 3693
// // 
// // Question 2
// // Correct
// // Mark 1.00 out of 1.00
// // 2255
// // p = − 19
// // is a
// // a. pseudo-prime number
// // b. prime number
// // c. composite number
// // Your answer is correct.
// // The correct answer is:
// // prime number
// // 
// // Question 3
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the Elliptic curve EL: y2 = x3 + 5x + 3 under modulo 11.
// // ⊞ denotes the addition operation between two points on EL.
// // If P= (3, 1), Q= (0, 5) are two points on this curve then P ⊞ Q
// // will be
// // a. (0,6)
// // b. (1,8)
// // c. none of these
// // d. (0,5)
// // e. (1,3)
// // Your answer is correct.
// // The correct answer is:
// // (0,6)
// // 
// // Question 4
// // Correct
// // Mark 1.00 out of 1.00
// // Let H be a collision resistant hash function. Define a new hash
// // function H1 based on H in the following way.
// // H1(X) = H(X) if X \neq X0, H1(X) = H(X1) if X = X0 where X0 and X1 are
// // not equal. Is H1 collision resistant?
// // a. Yes
// // b. No
// // 
// // Your answer is correct.
// // The correct answer is:
// // No
// // Question 5
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider the RSA encryption algorithm with N=pq, here p,q are
// // large primes. Let the encryption key be e=3.
// // The encryption of the message m is c1 and encryption of the
// // message m+1 is c2. Is it possible to find m from c1 and c2 with out
// // performing decryption?
// // a. No 
// // b. Yes
// // Your answer is incorrect.
// // The correct answer is:
// // Yes
// // Question 6
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider AES-256 bit encryption algorithm and CBC modes of operation.
// // Using AES-256 in CBC mode we define a CBC-MAC. Let M1 be a message of
// // 256 bit and CBC-MAC corresponding to M1 be T1. Let M1=m1 || m2 where
// // each m1 and m2 is of 128 bits. The MAC corresponding
// // to M2=M1 || (m2 \oplus T1) will be,
// // a. C=AES-256(m2)
// // b. T1 || C where C=AES-256(m2 \oplus T1)
// // c. T1
// // d.
// // None of these
// // 
// // e. C=AES-256(m2 \oplus T1)
// // Your answer is incorrect.
// // The correct answer is:
// // C=AES-256(m2)
// // Question 7
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the prime number p=2267 and the group \mathbb{Z}_p^* with
// // multiplication modulo p operation. Let g=2 be a generator of the group \mathbb{Z}_p^*
// // .
// // Alice and Bob now would like to establish a common secret key using
// // Diffie-Hellman key exchange protocol on the above mentioned group.
// // The secret key of Alice and Bob are 1197 and 62 respectively. Which of the
// // following statement is correct.
// // a. Alice's public key = 1965, Bob's public key = 1209, Common secret key = 1459
// // b. none of these
// // c. Alice's public key = 1758, Bob's public key = 1528, Common secret key = 1980
// // d. Alice's public key = 1284, Bob's public key = 1975, Common secret key = 1890
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 1965, Bob's public key = 1209, Common secret key = 1459
// // Question 8
// // Correct
// // Mark 1.00 out of 1.00
// // Forward secrecy implies end to end encryption
// // a. True
// // b. False
// // Your answer is correct.
// // The correct answer is:
// // False
// // 
// // 
// // Question 9
// // Correct
// // Mark 1.00 out of 1.00
// // In Signal protocol the initial secret key that will be established
// // between two users is
// // a. SHA-256(concatenation of Diffie-Hellman shared keys)
// // b. SHA-256(concatenation of Diffie-Hellman shared keys and 1)
// // c. Concatenation of SHA-256(Diffie-Hellman shared keys)
// // d. Diffie-Hellman shared key
// // Your answer is correct.
// // The correct answer is:
// // SHA-256(concatenation of Diffie-Hellman shared keys)
// // 
// // Question 10
// // Incorrect
// // Mark 0.00 out of 1.00
// // We define the following two problems Computational Diffie-Hellman (CDH)
// // problem and Discrete Log (DL) problem :
// // CDH: Given p, g, g^a and g^b compute g^{ab}
// // DL: Given p, g and g^a, find a.
// // Here p is a large prime number and g is a generator of the cyclic
// // group \mathbb{Z}_p^* with multiplication modulo p operation. Which of
// // the following statement is most accurate?
// // a. If DL is solved then CDH is also solved
// // b. If CDH is solved then DL is also solved
// // c. DL and CDH both are equivalent
// // Your answer is incorrect.
// // The correct answer is:
// // If DL is solved then CDH is also solved
// // 
// // Question 11
// // Incorrect
// // Mark 0.00 out of 1.00
// // CBC-MAC constructed using AES-512 will have MAC size
// // a. Depends on the message size
// // b. 128 bit
// // c. 256 bit
// // d. 512 bit
// // Your answer is incorrect.
// // The correct answer is:
// // 128 bit
// // 
// // Question 12
// // Incorrect
// // Mark 0.00 out of 1.00
// // Select the most appropriate option. During the registration phase
// // in Signal protocol the user
// // a. uploads public key of identity key, signed prekey, and signature on public key of signed prekey
// // b. uploads public key of identity key, signed prekey
// // c. uploads public key of identity key, signed prekey, ephemeral key and signature on public key of signed prekey
// // d. uploads public key of identity key, signed prekey, and signature on public key of identity key
// // Your answer is incorrect.
// // The correct answer is:
// // uploads public key of identity key, signed prekey, and signature on public key of signed prekey
// // Question 13
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider the RSA encryption RSA-Enc algorithm and construct the
// // bit-generator G defined as follows.
// // G( K)= z = j-th bit of c. Here c = RSA-Enc( K) = Which of following statement is correct?
// // K^e\mod n and j is fixed.
// // a. G is not Pseudorandom
// // b. G is Pseudorandom
// // Your answer is incorrect.
// // The correct answer is:
// // G is Pseudorandom
// // 
// // 
// // Question 14
// // Correct
// // Mark 1.00 out of 1.00
// // Let g:\{0,1\}^{256} \rightarrow \{0,1\}^{256} be any preimage
// // resistant function. Define f:\{0,1\}^{512} \rightarrow \{0,1\}^{512}
// // by using the following rule:
// // f(x
// // _
// // 0,\ldots,x
// // _{511})=1^{512} \text{ if } x
// // 0=x
// // 1=\cdots =x
// // _
// // _
// // _{255}=1
// // f(x
// // _
// // 0,\ldots,x
// // _{511})=1^{256}||g(x
// // _{256},\ldots ,x
// // _{511}) \text{ otherwise}
// // Here 1^d denotes a d-bits string whose all bits are one. Which of the
// // following statement is true?
// // a. f is preimage resistant function
// // b. f is not preimage resistant function
// // Your answer is correct.
// // The correct answer is:
// // f is preimage resistant function
// // 
// // Question 15
// // Correct
// // Mark 1.00 out of 1.00
// // A trapdoor function is a function that is easy to compute in one
// // direction, yet difficult to compute in the opposite direction (finding
// // its inverse) without special information, called the "trapdoor"
// // .
// // Which of the following statement is correct?
// // a. RSA encryption is a trapdoor function with public key is the trapdoor
// // b. RSA encryption is a trapdoor function with private key is the trapdoor
// // c. Public key encryption function can not be a trapdoor function
// // Your answer is correct.
// // The correct answer is:
// // RSA encryption is a trapdoor function with private key is the trapdoor
// // 
// // Question 16
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider the Elliptic curve EL: y^2=x^3+6x+3 under modulo 17.
// // \boxplus denotes the addition operation between two points on EL.
// // If P=(16,8), Q=(15,0) are two points on this curve then P\boxplus Q
// // will be
// // a. (8,11)
// // b. (16,9)
// // c. none of these
// // d. (9,2)
// // e. (6,0)
// // Your answer is incorrect.
// // The correct answer is:
// // (16,9)
// // 
// // Question 17
// // Correct
// // Mark 1.00 out of 1.00
// // AES-Mixcolumn(160, 189, 63, 98) [all are in decimal]
// // a. 165, 179, 213, 25
// // b. 211, 100, 225, 123
// // c. 18, 23, 16, 21
// // d. none of these
// // e. 218, 226, 197, 189
// // Your answer is correct.
// // The correct answer is:
// // 218, 226, 197, 189
// // 
// // Question 18
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the prime number p=353 and the group \mathbb{Z}_p^* with
// // multiplication modulo p operation. Let g=3 be a generator of the group
// // \mathbb{Z}_p^*.
// // Alice and Bob now would like to establish a common secret key using
// // Diffie-Hellman key exchange protocol on the above mentioned group.
// // The secret key of Alice and Bob are 97 and 233 respectively. Which of the
// // following statement is correct.
// // a. Alice's public key = 340, Bob's public key = 28, Common secret key = 210
// // b. None of these
// // c. Alice's public key = 240, Bob's public key = 48, Common secret key = 130
// // d. Alice's public key = 40, Bob's public key = 248, Common secret key = 160
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 40, Bob's public key = 248, Common secret key = 160
// // 
// // Question 19
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the Elliptic curve EL: y^2=x^3+5x+3 under modulo 13.
// // \boxplus denotes the addition operation between two points on EL.
// // If P=(9,7), Q=(4,3) are two points on this curve then P\boxplus Q
// // will be
// // a. (8,3)
// // b. (8,10)
// // c. (13,10)
// // d. none of these
// // e. (10,0)
// // Your answer is correct.
// // The correct answer is:
// // (10,0)
// // 
// // Question 20
// // Incorrect
// // Mark 0.00 out of 1.00
// // If g is a generator of the group Z
// // _
// // m^{*} where
// // Z
// // _
// // m^{*}=\{x~|~\gcd(x,m)=1 \} (m is not a prime) then what is the
// // order of g?
// // a.
// // m-1
// // b. \phi(m)
// // c. (m-1)(m-2)
// // Your answer is incorrect.
// // The correct answer is:
// // \phi(m)
// // 
// // Question 21
// // Correct
// // Mark 1.00 out of 1.00
// // Which of the following is true for forward secrecy?
// // a. forward secrecy implies perfect secrecy
// // b. if Pr[m0|c0] is known then Pr[m1|c1] will also be known
// // c. if Pr[m1|c1] is known then Pr[m0|c0] will also be known
// // d. if the security of present message is compromised still the security of previous messages remain unaffected
// // Your answer is correct.
// // The correct answer is:
// // if the security of present message is compromised still the security of previous messages remain unaffected
// // 
// // Question 22
// // Incorrect
// // Mark 0.00 out of 1.00
// // If n = pq, where p, q are large primes. We state the following problems P1 and P2:
// // P1: Find p, q from n.
// // P2: Compute \phi(n) without knowing p, q.
// // Which of the following statement is true?
// // a. Solving P2 is harder than P1.
// // b.
// // Problems P1 and P2 are equivalent.
// // c. Solving P1 is harder than P2.
// // Your answer is incorrect.
// // The correct answer is:
// // Problems P1 and P2 are equivalent.
// // 
// // Question 23
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the prime number p=3319 and the group \mathbb{Z}_p^* with
// // multiplication modulo p operation. Let g = 6 be a generator of the group \mathbb{Z}_p^*
// // .
// // Alice and Bob now would like to establish a common secret key using
// // Diffie-Hellman key exchange protocol on the above mentioned group.
// // The secret key of Alice and Bob are 1197 and 62 respectively. Which of the
// // following statement is correct.
// // a. Alice's public key = 1582, Bob's public key = 1758, Common secret key = 1890
// // b. Alice's public key = 1758, Bob's public key = 1582, Common secret key = 1890
// // c. none of these
// // d. Alice's public key = 1658, Bob's public key = 1528, Common secret key = 1980
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 1758, Bob's public key = 1582, Common secret key = 1890
// // 
// // Question 24
// // Correct
// // Mark 1.00 out of 1.00
// // Let n = 43 * 73 and the encryption key of RSA be e = 1195.
// // For the message M = 1234 which of the following statement is true.
// // a. the decryption key d = 787, ciphertext C = 760
// // b. the decryption key d = 760, ciphertext C = 787
// // c. none of these
// // d. the decryption key d = 777, ciphertext C = 760
// // Your answer is correct.
// // The correct answer is:
// // the decryption key d = 787, ciphertext C = 760
// // Question 25
// // Correct
// // Mark 1.00 out of 1.00
// // The key derivation function of the Signal protocol is
// // a. an invertible function
// // b. an one to one function
// // c. an one way function
// // Your answer is correct.
// // The correct answer is:
// // an one way function
// // 
// // 
// // Question 26
// // Correct
// // Mark 1.00 out of 1.00
// // Consider the AES-128 key-scheduling algorithm.
// // If K0, K1, ... , K10 denotes the 11 round keys corresponding to the
// // secret key K (in hexadecimal),
// // K = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// // Then K1 (in hexadecimal) is
// // a. c0 39 34 78 84 6c 52 0f 0c f5 f8 b4 c0 28 16 4b
// // b. d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe
// // c. c1 84 21 af ed 10 c0 2a 45 fb 89 de 5d a3 52 a5
// // d. none of these
// // e. 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// // Your answer is correct.
// // The correct answer is:
// // c0 39 34 78 84 6c 52 0f 0c f5 f8 b4 c0 28 16 4b
// // 
// // Question 27
// // Incorrect
// // Mark 0.00 out of 1.00
// // Which of the following technique is followed in the SSL record protocol
// // to achieve confidentiality as well as integrity?
// // a. None of these
// // b. Encryption((MAC(compressed data)) || Encryption(compressed data)
// // c. Encryption (compressed data || MAC(compressed data))
// // d. Encryption(compressed data) || MAC(compressed data)
// // Your answer is incorrect.
// // The correct answer is:
// // Encryption (compressed data || MAC(compressed data))
// // Question 28
// // Incorrect
// // Mark 0.00 out of 1.00
// // Let n be a product of two large primes i.e., n = p*q. We know that
// // finding p, q from n is a computationally hard problem. If I give you n
// // along with \phi(n) then will you be able to find p, q in polynomial time?
// // a. No
// // b. Yes
// // Your answer is incorrect.
// // The correct answer is:
// // Yes
// // 
// // 
// // Question 29
// // Correct
// // Mark 1.00 out of 1.00
// // Let n = 17 * 11 = 187 and the encryption key of RSA be e = 7.
// // For the message M = 88 which of the following statement is true.
// // a. the decryption key d = 13, ciphertext C = 21
// // b. the decryption key d = 21, ciphertext C = 11
// // c. the decryption key d = 23, ciphertext C = 11
// // Your answer is correct.
// // The correct answer is:
// // the decryption key d = 23, ciphertext C = 11
// // Question 30
// // Incorrect
// // Mark 0.00 out of 1.00
// // Select the most appropriate option.
// // In Signal protocol perfect secrecy is achieved
// // a. by deleting previous root key and using SHA-256
// // b. by deleting previous root key, previous chain key and using SHA-256
// // c. by deleting previous root key, previous chain key, previous message key and by using SHA-256
// // Your answer is incorrect.
// // The correct answer is:
// // by deleting previous root key, previous chain key, previous message key and by using SHA-256
// // 
// // 
// // Question 31
// // Incorrect
// // Mark 0.00 out of 1.00
// // The initial message in Signal protocol is encrypted using
// // a. AES-256 in CBC mode on (Message || MAC on the message)
// // b. AES-256 in CTR mode with signature based encryption
// // c.
// // authenticated encryption with associated data using AES-256
// // Your answer is incorrect.
// // The correct answer is:
// // authenticated encryption with associated data using AES-256
// // Question 32
// // Incorrect
// // Mark 0.00 out of 1.00
// // In SSL the sequence number of the sending data and receiving
// // data is a part of
// // a. session state
// // b. connection state
// // Your answer is incorrect.
// // The correct answer is:
// // connection state
// // 
// // 
// // Question 33
// // Correct
// // Mark 1.00 out of 1.00
// // We define a new encryption algorithm TEnc using AES-128 encryption
// // technique.
// // TEnc : \{0,1\}^{384}\times \{0,1\}^{128} \rightarrow \{0,1\}^{128} where
// // C = TEnc(K||K1||K2, M) = K2 \oplus AES-128-Enc(K, K1 \oplus M).
// // Here K, K1, K2 each is of 128 bit. What will be the decryption algorithm
// // (TDec) corresponding to TEnc.
// // a. None of these
// // b.
// // M = TDec(K||K1||K2, C) = K1 \oplus AES-128-Dec(K, K2 \oplus C) 
// // c. M = TDec(K||K1||K2, C) = K2 \oplus AES-128-Dec(K, K1 \oplus C)
// // d. M = TDec(K||K1||K2, C) = K \oplus AES-128-Dec(K1, K2 \oplus C)
// // Your answer is correct.
// // The correct answer is:
// // M = TDec(K||K1||K2, C) = K1 \oplus AES-128-Dec(K, K2 \oplus C)
// // Question 34
// // Incorrect
// // Mark 0.00 out of 1.00
// // In which message of the SSL protocol, server sends its random number?
// // a. in server's hello message
// // b. in change cipher message
// // 
// // c. in handshake message
// // d. inside record header
// // Your answer is incorrect.
// // The correct answer is:
// // in server's hello message
// // Question 35
// // Correct
// // Mark 1.00 out of 1.00
// // Let F be a preimage resistant function from S to S. Consider a new
// // function G = F o F (i.e., F compose F).
// // Which of the following statement is true?
// // a. G is a preimage resistant function
// // b.
// // G need not be a preimage resistant function 
// // Your answer is correct.
// // The correct answer is:
// // G need not be a preimage resistant function
// // Question 36
// // Not answered
// // Marked out of 1.00
// // Select the most appropriate option. Signal protocol provides
// // a. end to end encryption, forward secrecy only
// // b. end to end encryption, forward secrecy and handles out of order messages
// // c. end to end encryption only
// // Your answer is incorrect.
// // The correct answer is:
// // end to end encryption, forward secrecy and handles out of order messages
// // Question 37
// // Not answered
// // Marked out of 1.00
// // A 5-bit LFSR is constructed using the connection polynomial
// // f(x)=x^5+x^4+x^2+x+1. The period of this LFSR will be
// // a. 31
// // b. none of these
// // c. 63
// // d. 30
// // e. 15
// // Your answer is incorrect.
// // The correct answer is:
// // 31
// // Question 38
// // Not answered
// // Marked out of 1.00
// // If the two fragmented data are identical in SSL Record protocol, then
// // which of the following statement is correct?
// // a. the corresponding encrypted data will be identical as the compressed data will be the same
// // b. the corresponding encrypted data will be different
// // c. nothing can be said
// // Your answer is incorrect.
// // The correct answer is:
// // the corresponding encrypted data will be different
// // Question 39
// // Not answered
// // Marked out of 1.00
// // Certificate is a
// // a. signed public key of an user signed by some trusted party
// // b. MAC of an user's public key generated by some trusted party
// // c. signed private key of an user signed by some trusted party
// // d. signed public key of user signed by the same user
// // Your answer is incorrect.
// // The correct answer is:
// // signed public key of an user signed by some trusted party
// // Question 40
// // Not answered
// // Marked out of 1.00
// // Let n=pq where p,q are primes. Consider e such that
// // \gcd(e,\phi(n))=1 [here \phi is the Euler's totient function].
// // The function defined by f(x)=x^e\mod n is
// // a. not a permutation on \mathbb{Z}_
// // n^*
// // b. none of these
// // c. a permutation on \mathbb{Z}_
// // n^*
// // Your answer is incorrect.
// // The correct answer is:
// // a permutation on \mathbb{Z}_
// // n^*
// // ◄ Midterm
// // Jump to...
// // Dashboard / Courses / Autumn 2024-25/ B.Tech Semester 5/ CS309_2024/ General / Pre Mid Term Class Test
// // Started onMonday, 30 September 2024, 2:10 PM
// // State Finished
// // Completed onMonday, 30 September 2024, 2:34 PM
// // Time taken 24 mins 21 secs
// // Grade 6.50 out of 10.00 (65%)
// // Question 1
// // Correct
// // Mark 0.50 out of 0.50
// // Using Euclidean algorithm find (x, y) such that 1 = 7x+ 26y.
// // a.(11, -3)
// // c.(11, 3)
// // d.none of these
// // e.(-11, 5)
// // b.(-11, 3) 
// // Your answer is correct.
// // The correct answer is:
// // (-11, 3)
// // 
// // Question 2
// // Incorrect
// // Mark 0.00 out of 0.50
// // We define a new encryption algorithm TEnc using AES-128 encryption
// // technique.
// // TEnc : where
// // {0, 1 × {0, 1 → {0, 1
// // }384 }128 }128
// // ⊕ ⊕
// // C = TEnc(K||K1||K2, M) = K2 AES-128-Enc(K, K1 M).
// // Here K, K1, K2 each is of 128 bit. What will be the decryption algorithm
// // (TDec) corresponding to TEnc.
// // a.M = TDec(K||K1||K2, C) = K AES-128-Dec(K1, K2 C)
// // ⊕ ⊕
// // ⊕ ⊕
// // b.M = TDec(K||K1||K2, C) = K1 AES-128-Dec(K, K2 C)
// // c.M = TDec(K||K1||K2, C) = K2 AES-128-Dec(K, K1 C) 
// // ⊕ ⊕
// // d.None of these
// // Your answer is incorrect.
// // The correct answer is:
// // ⊕ ⊕
// // M = TDec(K||K1||K2, C) = K1 AES-128-Dec(K, K2 C)
// // 
// // Question 3
// // Correct
// // Mark 0.50 out of 0.50
// // Under which condition OTP provides perfect secrecy?
// // a.all are correct
// // b.Secret key is selected randomly, secret key is as large as the plaintext
// // c.Secret key is selected randomly, secret key is as large as the plaintext, secret key is not repeated for doing encryption
// // of two messages
// // d.Secret key is as large as the plaintext, secret key is not repeated for doing encryption of two messages
// // e.Secret key is selected randomly, secret key is not repeated for doing encryption of two messages
// // 
// // Your answer is correct.
// // The correct answer is:
// // messages
// // Secret key is selected randomly, secret key is as large as the plaintext, secret key is not repeated for doing encryption of two
// // Question 4
// // Incorrect
// // Mark 0.00 out of 0.50
// // 𝐶= 𝑃 ⊕ 𝐾 𝑃 𝑟[𝐾 = 0] = 0.5 Consider one-bit encryption . If and
// // 𝑃 𝑟[𝑃 = 1] = 0.2
// // then is
// // 𝑃 𝑟[𝑃 = 1|𝐶= 1]
// // a.0.5
// // b.0.8
// // c.0.7 
// // d.0.2
// // e.none of these
// // Your answer is incorrect.
// // The correct answer is:
// // 0.2
// // 
// // Question 5
// // Incorrect
// // Mark 0.00 out of 0.50
// // Select the correct answer where S : {0,1} → {0,1} and S :{0,1} → {0,1} are the first two
// // 1 6 4 2 6 4
// // defined S-boxes for the round function of DES. (For the description of these S-boxes please
// // see Handbook of Applied Cryptography book.)
// // a.S (59) = 0, S (23) = 10.
// // 1 2
// // b.S (59) = 4, S (23) = 8
// // 1 2
// // c.S (59) = 1, S2(23) = 10.
// // 1
// // d.S (59) = 0, S (23) = 14. 
// // 1 2
// // Your answer is incorrect.
// // The correct answer is:
// // S (59) = 0, S (23) = 10.
// // 1 2
// // Question 6
// // Correct
// // Mark 0.50 out of 0.50
// // If AES-Mixcolumn(23, 67, 45, 89) = (x,y,z,w) then y =
// // [here input and output are in integer]
// // a.229
// // b.121
// // c.159
// // d.191 
// // Your answer is correct.
// // The correct answer is:
// // 191
// // 
// // Question 7
// // Correct
// // Mark 0.50 out of 0.50
// // A sequence of plaintext blocks x1,...,xn are encrypted by
// // using AES-128 in CBC mode. The corresponding ciphertext blocks
// // are y1,...,yn. During transmission y1 is transmitted incorrectly
// // (i.e., some 1's are changed to 0's and vice verse).
// // The number of plaintext blocks that will be decrypted incorrectly is
// // a.3
// // b.2 
// // c.1
// // d.none of these
// // e.
// // n
// // Your answer is correct.
// // The correct answer is:
// // 2
// // 
// // Question 8
// // Correct
// // Mark 0.50 out of 0.50
// // If g is a generator of the group 𝑍∗
// // 𝑚
// // = {𝑥 | gcd(𝑥, 𝑚) = 1}
// // order of g?
// // 𝑍∗
// // 𝑚
// // where
// // (m is not a prime) then what is the
// // a. 
// // 𝜙(𝑚)
// // b.
// // (𝑚− 1)(𝑚− 2)
// // c.
// // 𝑚− 1
// // Your answer is correct.
// // The correct answer is:
// // 𝜙(𝑚)
// // 
// // Question 9
// // Correct
// // Mark 0.50 out of 0.50
// // Expanded key size of AES-256 is
// // a.48 words
// // b.56 words
// // c.60 words
// // 
// // d.44 words
// // e.none of these
// // Your answer is correct.
// // The correct answer is:
// // 60 words
// // Question 10
// // Correct
// // Mark 0.50 out of 0.50
// // How many words need to be generated in AES-192 key scheduling algorithm.
// // a.48
// // b.none of these
// // c.52 
// // d.44
// // Your answer is correct.
// // The correct answer is:
// // 52
// // 
// // Question 11
// // Correct
// // Mark 0.50 out of 0.50
// // Consider AES-256 bit encryption algorithm and a 512 bit key K=K1||K2 where K1 and K2 are of 256 bit.
// // The encryption algorithm C=AES-256(AES-256(M,K1),K2) provides
// // a.512-bit security
// // b.256-bit security
// // 
// // Your answer is correct.
// // The correct answer is:
// // 256-bit security
// // Question 12
// // Incorrect
// // Mark 0.00 out of 1.00
// // Consider DES encryption key K=11....1 (all one).
// // If C=DES-ENC(P,K) then DES-ENC(C,K)=?
// // a.Complement of C
// // b.none of these 
// // c.P
// // d.Complement of P
// // Your answer is incorrect.
// // The correct answer is:
// // P
// // 
// // Question 13
// // Incorrect
// // Mark 0.00 out of 0.50
// // Which is the correct multiplicative inverse of the polynomial ℤ 2 𝑥8 𝑥4 𝑥3
// // [𝑥]/ + + + 𝑥 + 1
// // .
// // 𝑥7 𝑥5 𝑥4 𝑥2
// // 𝑔(𝑥) = + + + + 1
// // in
// // a.
// // 𝑥6 𝑥5 𝑥4 𝑥2
// // + + + + 1
// // b.none of these 
// // c.
// // 𝑥4 𝑥3 𝑥2
// // + + + 𝑥 + 1
// // d.
// // 𝑥4 𝑥2
// // + + 𝑥 + 1
// // Your answer is incorrect.
// // The correct answer is:
// // 𝑥6 𝑥5 𝑥4 𝑥2
// // + + + + 1
// // Question 14
// // Correct
// // Mark 0.50 out of 0.50
// // AES-Subbytes (52)
// // a.01
// // b.ED
// // c.none of these
// // d.D1
// // e.00 
// // Your answer is correct.
// // The correct answer is:
// // 00
// // 
// // Question 15
// // Correct
// // Mark 0.50 out of 0.50
// // What is the period of the 5-bit LFSR whose connection polynomial is
// // 𝑥8 𝑥4 𝑥3
// // + + + 𝑥 + 1
// // a.160
// // b.255 
// // c.256
// // d.none of these
// // e.155
// // Your answer is correct.
// // The correct answer is:
// // 255
// // Question 16
// // Incorrect
// // Mark 0.00 out of 0.50
// // Which is the correct multiplicative inverse of the polynomial 𝑥7 𝑥5 𝑥4
// // 𝑔(𝑥) = + + + 1
// // in Z [x]/x +x +x +x+1.
// // 2 8 4 3
// // a.none of these 
// // b.
// // 𝑥7 𝑥6 𝑥3
// // + +
// // c.
// // 𝑥7 𝑥6 𝑥5
// // + +
// // d.
// // 𝑥7 𝑥6
// // + + 𝑥
// // Your answer is incorrect.
// // The correct answer is:
// // 𝑥7 𝑥6 𝑥5
// // + +
// // 
// // Question 17
// // Correct
// // Mark 0.50 out of 0.50
// // Suppose that K = (5, 21) is a key in an Affine Cipher over can be expressed as , where .
// // 𝑑𝐾 𝑎′ 𝑏′
// // (𝑦) = 𝑦 +
// // 𝑎′ 𝑏′ ℤ 31
// // , ∈
// // . The decryption function
// // 𝑑𝐾
// // ℤ 31 (𝑦)
// // a.
// // none of these
// // b. 
// // 𝑎′ 𝑏′
// // = 25,
// // = 2
// // c.
// // 𝑎′ 𝑏′
// // = 23,
// // = 3
// // d.
// // 𝑎′ 𝑏′
// // = 2,
// // = 25
// // Your answer is correct.
// // The correct answer is:
// // 𝑎′ 𝑏′
// // = 25,
// // = 2
// // Question 18
// // Correct
// // Mark 0.50 out of 0.50
// // Consider one round of Feistel network with the block size 64-bit and the secret key size 32-bit.
// // The round f
// // 32
// // unction is defined by f (R, K) = S (R ⊕ K) where S (X ) = (X + 1) mod 2 .
// // Find the ciphertext for the plaintext = 1 and key K = 1.
// // a.2147483649
// // b.4294967296
// // c.4294967297 
// // d.2147483648
// // e.none of these
// // Your answer is correct.
// // The correct answer is:
// // 4294967297
// // 
// // Question 19
// // Correct
// // Mark 0.50 out of 0.50
// // If AES-Mixcolumn(23, 66, 89, 44) = (x,y,z,w) then w =
// // [here input and output are in integer]
// // a.122 
// // b.159
// // c.145
// // d.none of these
// // e.121
// // Your answer is correct.
// // The correct answer is:
// // 122
// // ◀ Test Quiz
// // Jump to...
// // 
// // 2/29/24, 5:39 PM CS364 (LAB ) Test: Attempt review
// // Dashboard / My courses / CS 364_2022 / General / CS364 (LAB ) Test
// // Started on Tuesday, 18 April 2023, 2:36 PM
// // State Finished
// // Completed on Time taken Tuesday, 18 April 2023, 3:06 PM
// // 30 mins 1 sec
// // Grade 8.00 out of 10.00 (80%)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 1/12
// // 2/29/24, 5:39 PM Question 1
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // Consider RSA cryptosystem with p = 761, q = 769 and e = 941.
// // Here public key = (n, e), private key = (p, q, d)
// // Consider the message m = 600.
// // Select the appropriate option.
// // a. e is legitimate, d = 43141, ciphertext = 48006
// // b. e is legitimate, d = 44141, ciphertext = 48006
// // c. e is legitimate, d = 47141, ciphertext = 48006 
// // d. e is not legitimate, thus none of these
// // e. e is legitimate, d = 4741, ciphertext = 48006
// // Your answer is correct.
// // The correct answer is:
// // e is legitimate, d = 47141, ciphertext = 48006
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 2/12
// // 2/29/24, 5:39 PM Question 2
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // Z∗
// // p
// // with multiplication mod p operation.
// // Consider the Diffie-Hellman key exchange on the Group Let p = 3319 and generator of the group g = 6.
// // Alice's secret key = 1197, Bob's secret key = 62.
// // Select the most appropriate option.
// // a. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890 
// // b. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1891
// // c. Alice's public key = 1658, Bob's public key = 1582, Shared secret key = 1890
// // d. Alice's public key = 1582, Bob's public key = 1758, Shared secret key = 1890
// // e. none of these
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 3/12
// // 2/29/24, 5:39 PM Question 3
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // y2 x3 ×
// // Consider the Elliptic curver E: defined over .
// // = + 13x + 23
// // Z29 Z29
// // What is the addition of two points (16 , 21) and (9, 12)?
// // a. (24, 6) 
// // b. (7, 14)
// // c. (8, 28)
// // d. None of these
// // e. (16, 21)
// // Your answer is correct.
// // The correct answer is:
// // (24, 6)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 4/12
// // 2/29/24, 5:39 PM Question 4
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // y2 x3 ×
// // Consider the Elliptic curve E: defined over .
// // = + 11x + 23
// // Z43 Z43
// // What is the addition of two points (11, 23) and (26, 30)?
// // a. (7, 20)
// // b. (31, 38)
// // c. (38, 31)
// // d. (41, 6) 
// // e. (6, 41)
// // Your answer is correct.
// // The correct answer is:
// // (41, 6)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 5/12
// // 2/29/24, 5:39 PM Question 5
// // Incorrect
// // Mark 0.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // AES-MIXCOLUMN (234, 56, 118, 221,)
// // a. (54, 221, 63, 202)
// // b. (44, 221, 66, 202)
// // c. (44, 220, 66, 202)
// // d. none of these
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 6/12
// // 2/29/24, 5:39 PM CS364 (LAB ) Test: Attempt review
// // e. (44, 221, 66, 201) 
// // Your answer is incorrect.
// // The correct answer is:
// // (44, 221, 66, 202)
// // Question 6
// // Correct
// // Mark 1.00 out of
// // 1.00
// // Consider the Diffie-Hellman key exchange on the Group Z∗
// // p
// // with multiplication mod p operation.
// // Let p = 2689 and generator of the group g = 19.
// // Alice's secret key = 119, Bob's secret key = 62.
// // Select the most appropriate option.
// // a. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409 
// // b. Alice's public key = 1630 , Bob's public key = 2563 , Common secret key = 2409
// // c. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2309
// // d. Alice's public key = 1631 , Bob's public key = 2573 , Common secret key = 2409
// // e. none of these
// // Your answer is correct.
// // The correct answer is:
// // Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 7/12
// // 2/29/24, 5:39 PM Question 7
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // y2 x3 ×
// // Consider the Elliptic curve E: defined over .
// // = + 23x + 11
// // Z173 Z173
// // What is the addition of two points (28 ,109) and (88, 147)?
// // a. (112, 92)
// // b. none of these
// // c. (8,19) 
// // d. (133, 73)
// // e. (138, 10)
// // Your answer is correct.
// // The correct answer is:
// // (8,19)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 8/12
// // 2/29/24, 5:39 PM Question 8
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // AES-INV-MIXCOLUMN (123, 202, 87, 77)
// // a. (114, 54, 143, 96)
// // b. (52, 215, 139, 72)
// // c. none of these
// // d. (157, 132, 225, 110)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 9/12
// // 2/29/24, 5:39 PM CS364 (LAB ) Test: Attempt review
// // e. (54, 69, 87, 143) 
// // Your answer is correct.
// // The correct answer is:
// // (54, 69, 87, 143)
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 10/12
// // 2/29/24, 5:39 PM Question 9
// // Incorrect
// // Mark 0.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // Consider RSA cryptosystem with p = 691, q = 701 and e = 563.
// // Here public key = (n, e), private key = (p,q,d)
// // Consider the message m = 600.
// // Select the appropriate option.
// // a. e is legitimate, d = 62617, ciphertext = 315318 
// // b. e is legitimate, d = 62727, ciphertext = 315318
// // c. e is legitimate, d = 61627, ciphertext = 315318
// // d. e is legitimate, d = 62627, ciphertext = 315318
// // e. e is not legitimate, thus none of these
// // Your answer is incorrect.
// // The correct answer is:
// // e is legitimate, d = 62627, ciphertext = 315318
// // https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=108404&cmid=3587 11/12
// // 2/29/24, 5:39 PM Question 10
// // Correct
// // Mark 1.00 out of
// // 1.00
// // CS364 (LAB ) Test: Attempt review
// // AES-INV-MIXCOLUMN (123, 212, 88, 77) [inputs are in decimal]
// // a. (175, 152, 227, 110) 
// // b. (175, 15, 227, 110)
// // c. none of these
// // d. (75, 152, 227, 110)
// // e. (175, 152, 27, 110)
// // Your answer is correct.
// // The correct answer is:
// // (175, 152, 227, 110)

// 4/30/24, 1:46 PM LAB test: Attempt review
// Dashboard / Courses / Winter 2023-24 / B.Tech Semester 6 / CS364_2024 / General / LAB test
// Started on Friday, 1 March 2024, 11:33 AM
// State Finished
// Completed on Time taken Friday, 1 March 2024, 11:53 AM
// 20 mins 1 sec
// Grade 3.00 out of 9.00 (33%)
// Question 1
// Incorrect
// Mark 0.00 out of 1.00
// MIXCOLUMN (32, 198, 201, 35) = ?
// when we work on .
// F2 x8 x4 x3 x2
// [x]/ < + + + + 1 >
// Input, output are in decimal.
// a. (251, 212, 10, 41) 
// b. (231, 18, 101, 55)
// c. none of these
// d. (253, 212, 12, 41)
// e. (211, 213, 17, 37)
// Your answer is incorrect.
// The correct answer is:
// (253, 212, 12, 41)
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 1/6
// 4/30/24, 1:46 PM Question 2
// Correct
// Mark 1.00 out of 1.00
// LAB test: Attempt review
// Consider a Playfair cipher with key = aedoqmw
// What is the correct ciphertext of the plaintext = iamd
// a. gdba 
// b. dgab
// c. hewe
// d. ehew
// e. none of these
// Your answer is correct.
// The correct answer is:
// gdba
// Question 3
// Correct
// Mark 1.00 out of 1.00
// Let p = 2147483647. If a = 13 then the multiplicative inverse
// of a under mod p is =
// a. 1486719447
// b. 1486719448
// 
// c. none of these
// d. 1486619448
// e. 1486729448
// Your answer is correct.
// The correct answer is:
// 1486719448
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 2/6
// 4/30/24, 1:46 PM Question 4
// Incorrect
// Mark 0.00 out of 1.00
// LAB test: Attempt review
// MIXCOLUMN (32, 198, 201, 35) = ?
// when we work on .
// F2 x8 x6 x5 x4 x2
// [x]/ < + + + + + x + 1 >
// Input, output are in decimal.
// a. (151, 212, 102, 41)
// b. (151, 212, 102, 11)
// c. none of these
// d. (151, 202, 102, 41)
// e. (151, 102, 212, 41) 
// Your answer is incorrect.
// The correct answer is:
// (151, 212, 102, 41)
// Question 5
// Not answered
// Not graded
// Consider a modified Playfair cipher on
// { A, B, C, D,..., Z, \ , /, [ , ] } . Note that the set has 30 elements.
// Consider the key = AETIMPSB and select the encryption of
// plaintext = CRYPTO\N
// a. QDUDWBEV
// b. QDUDBWEV
// c. QDUDBWVE
// d. none of these
// e. QDDUBWEV
// Your answer is incorrect.
// The correct answers are:
// QDUDBWEV,
// none of these
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 3/6
// 4/30/24, 1:46 PM Question 6
// Incorrect
// Mark 0.00 out of 1.00
// LAB test: Attempt review
// Consider AES-Subbyte table Sub().
// We define a new S-box from Sub as follows:
// S(x) = Sub((2*x)+1), here a*x and y+b are done in
// F2 x8 x6 x5 x4 x2
// [x]/ < + + + + + x + 1 >
// .
// What is value of S(212)? Here input, output are in decimal.
// a. 113
// b. 29
// c. 92 
// d. 28
// e. none of these
// Your answer is incorrect.
// The correct answer is:
// 29
// Question 7
// Correct
// Mark 1.00 out of 1.00
// CAESAR-Encryption ( aeqwg ) = ?
// a. dthjz
// b. dhtzq
// c. dhtzj 
// d. none of these
// e. ahtzj
// Your answer is correct.
// The correct answer is:
// dhtzj
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 4/6
// 4/30/24, 1:46 PM Question 8
// Incorrect
// Mark 0.00 out of 1.00
// LAB test: Attempt review
// Consider Affine encryption algorithm.
// If the secret key is K = (11,5), the ciphertext of the
// plaintext = aeswq is = ?
// a. fxvnz
// b. none of these
// c. fxvny 
// d. fzvnx
// e. fxnvz
// Your answer is incorrect.
// The correct answer is:
// fxvnz
// Question 9
// Incorrect
// Mark 0.00 out of 1.00
// Consider AES-Subbyte table Sub().
// We define a new S-box from Sub as follows:
// S(x) = Sub((2*x)+1), here a*x and y+b are done in
// F2 x8 x4 x3
// [x]/ < + + + x + 1 >
// .
// What is value of S(126)? Here input, output are in decimal.
// a. 48
// b. 84
// c. 83
// d. 88 
// e. none of these
// Your answer is incorrect.
// The correct answer is:
// 84
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 5/6
// 4/30/24, 1:46 PM Question 10
// Incorrect
// Mark 0.00 out of 1.00
// LAB test: Attempt review
// Consider Shift cipher and find the encryption of
// the plaintext = aeqwg
// where key = 5
// a. fjvlb
// b. none of these
// d. fvjbl 
// c. fjvbl
// e. fjvbp
// Your answer is incorrect.
// The correct answer is:
// fjvbl
// ◄ Announcements
// Jump to...
// LAB -Assignment 1 ►
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=154418&cmid=4421#question-174602-2 6/6
// 5/24/24, 4:50 PM Endterm Test: Attempt review
// Dashboard / Courses / Winter 2023-24 / B.Tech Semester 6 / CS364_2024 / General / Endterm Test
// Started on Tuesday, 30 April 2024, 9:50 AM
// State Finished
// Completed on Time taken Tuesday, 30 April 2024, 10:06 AM
// 16 mins 25 secs
// Grade 11.00 out of 11.00 (100%)
// Question 1
// Correct
// Mark 1.00 out of 1.00
// AES-MIXCOLUMN (234, 56, 118, 221) [Input/Output are in Decimal]
// a. (44, 221, 66, 202) 
// b. (44, 221, 66, 201)
// c. (44, 220, 66, 202)
// d. (54, 221, 63, 202)
// e. none of these
// Your answer is correct.
// Question 2
// Correct
// Mark 1.00 out of 1.00
// Consider the Diffie-Hellman key exchange on the Group Z∗
// p
// Let p = 3319 and generator of the group g = 6.
// Alice's secret key = 1197, Bob's secret key = 62.
// Select the most appropriate option.
// with multiplication mod p operation.
// a. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1890 
// b. Alice's public key = 1582, Bob's public key = 1758, Shared secret key = 1890
// c. none of these
// d. Alice's public key = 1658, Bob's public key = 1582, Shared secret key = 1890
// e. Alice's public key = 1758, Bob's public key = 1582, Shared secret key = 1891
// Your answer is correct.
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 1/6
// 5/24/24, 4:50 PM Question 3
// Correct
// Mark 1.00 out of 1.00
// Endterm Test: Attempt review
// Consider RSA cryptosystem with p = 691, q = 701 and e = 563.
// Here public key = (n, e), private key = (p,q,d)
// Consider the message m = 600.
// Select the appropriate option.
// a. e is not legitimate, thus none of these
// b. e is legitimate, d = 62727, ciphertext = 315318
// c. e is legitimate, d = 62627, ciphertext = 315318 
// d. e is legitimate, d = 61627, ciphertext = 315318
// e. e is legitimate, d = 62617, ciphertext = 315318
// Your answer is correct.
// Question 4
// Correct
// Mark 1.00 out of 1.00
// AES-INVERSE-MIXCOLUMN (123, 202, 87, 77) [Input/Output are in Decimal]
// a. (114, 54, 143, 96)
// b. (157, 132, 225, 110)
// c. none of these
// d. (52, 215, 139, 72)
// e. (54, 69, 87, 143) 
// Your answer is correct.
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 2/6
// 5/24/24, 4:50 PM Question 5
// Correct
// Mark 1.00 out of 1.00
// Endterm Test: Attempt review
// Consider RSA cryptosystem with p = 761, q = 769 and e = 941.
// Here public key = (n, e), private key = (p, q, d)
// Consider the message m = 600.
// Select the appropriate option.
// a. e is not legitimate, thus none of these
// b. e is legitimate, d = 47141, ciphertext = 48006 
// c. e is legitimate, d = 4741, ciphertext = 48006
// d. e is legitimate, d = 44141, ciphertext = 48006
// e. e is legitimate, d = 43141, ciphertext = 48006
// Your answer is correct.
// Question 6
// Correct
// Mark 1.00 out of 1.00
// Consider the Elliptic curve E: defined over .
// y2 x3 ×
// = + 11x + 23
// Z43 Z43
// What is the addition of two points (11, 23) and (26, 30)?
// a. (7, 20)
// b. (38, 31)
// c. (31, 38)
// d. (6, 41)
// e. (41, 6) 
// Your answer is correct.
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 3/6
// 5/24/24, 4:50 PM Question 7
// Correct
// Mark 1.00 out of 1.00
// Endterm Test: Attempt review
// AES-INVERSE-MIXCOLUMN (123, 212, 88, 77) [Input/Output are in Decimal]
// a. (75, 152, 227, 110)
// b. (175, 152, 227, 110) 
// c. (175, 152, 27, 110)
// d. none of these
// e. (175, 15, 227, 110)
// Your answer is correct.
// Question 8
// Correct
// Mark 1.00 out of 1.00
// Consider the Diffie-Hellman key exchange on the Group Z∗
// p
// with multiplication mod p operation.
// Let p = 2689 and generator of the group g = 19.
// Alice's secret key = 119, Bob's secret key = 62.
// Select the most appropriate option.
// a. Alice's public key = 1630 , Bob's public key = 2563 , Common secret key = 2409
// b. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2309
// c. Alice's public key = 2573 , Bob's public key = 1631 , Common secret key = 2409 
// d. Alice's public key = 1631 , Bob's public key = 2573 , Common secret key = 2409
// e. none of these
// Your answer is correct.
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 4/6
// 5/24/24, 4:50 PM Question 9
// Correct
// Mark 1.00 out of 1.00
// Endterm Test: Attempt review
// Consider the AES-128 key-scheduling algorithm.
// If K0, K1, ... , K10 denotes the 11 round keys corresponding to the
// secret key K (in hexadecimal),
// K = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// Then K1 (in hexadecimal) is
// a. c0 39 34 78 84 6c 52 0f 0c f5 f8 b4 c0 28 16 4b 
// b. none of these
// c. c1 84 21 af ed 10 c0 2a 45 fb 89 de 5d a3 52 a5
// d. d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe
// e. 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
// Your answer is correct.
// Question 10
// Correct
// Mark 1.00 out of 1.00
// = + 23x + 11
// Consider the Elliptic curve E: defined over .
// y2 x3 ×
// Z173 Z173
// What is the addition of two points (28 ,109) and (88, 147)?
// a. (112, 92)
// b. (8,19) 
// c. (138, 10)
// d. (133, 73)
// e. none of these
// Your answer is correct.
// https://betamoodle.iiitvadodara.ac.in/mod/quiz/review.php?attempt=164657&cmid=4537 5/6
// 5/24/24, 4:50 PM Question 11
// Correct
// Mark 1.00 out of 1.00
// Endterm Test: Attempt review
// Consider the Elliptic curve E: defined over .
// y2 x3 ×
// = + 13x + 23
// Z29 Z29
// What is the addition of two points (16 , 21) and (9, 12)?
// a. (24, 6) 
// b. (16, 21)
// c. (7, 14)
// d. None of these
// e. (8, 28)
// Your answer is correct.