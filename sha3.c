#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "sha3.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

uint32_t concatenate(uint8_t **Z, const uint8_t *X, uint32_t X_len, const uint8_t *Y, uint32_t Y_len);
uint32_t concatenate_01(uint8_t **Z, const uint8_t *X, uint32_t X_len);
uint32_t pad10x1(uint8_t **P, uint32_t x, uint32_t m);
uint8_t rc(uint32_t t);

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(uint8_t *d, uint32_t s, const uint8_t *m, uint32_t l)
{
        /* The hash size must be one of the supported ones */
        if (s != 224 && s != 256 && s != 384 && s != 512)
                return;

        /* Implement the rest of this function */

        uint8_t *M;


        concatenate_01(&M, m, l); // Concatenate m || 01 as is defined in SHA-3 specs

        sponge(&d, M, s, l+2); // l+2 due to 2 extra bits we concatenated with the input message above
        free(M);
}

/* Implement KECCAK-p[b,n_r](S)
 * m - input string of length b
 * S - pointer to KECCAK-modified string
 */
void keccak_p(uint8_t (*S)[200], uint8_t *m) {
        uint64_t state_arr[5][5];
        create_state_array(&state_arr, m); // Populate initial state array with the input message

        /* n_r - Number of Rnd-function iterations
         * i_r - Round index
         */
        int32_t n_r = 24, i_r, w_log = 6;
        for (i_r = 12 + 2*w_log - n_r; i_r <= 12 + 2*w_log - 1; i_r++) {
                theta(&state_arr);
                rho(&state_arr);
                pi(&state_arr);
                chi(&state_arr);
                iota(&state_arr, i_r);
        }

        // Convert state array back to a string
        convert_state_arr_to_str((*S), &state_arr);
}

/* Implement SPONGE construct to truncate/pad the input string to an output string of
 * length d
 * output - pointer to output string
 * N - pointer to input string
 * d - length of output string (in bits)
 * l - length of N in bits
 */
void sponge(uint8_t **output, uint8_t *N, uint32_t d, int32_t l) {
        int32_t b = 1600, r = 1088, c = 512, n, i, j;
        uint8_t *padding, *P, *P_i, *Z;
        uint8_t S[200] = {0}, S_cpy[200], arr_of_zeros[64] = {0}, S_XOR[200], S_Trunc_r[1088 / 8];
        uint32_t pad_length, P_len, Z_len = 0;

        pad_length = pad10x1(&padding, r, l); // pad(r, len(N))
        P_len = concatenate(&P, N, l, padding, pad_length); // N || pad(r, len(N))
        n = P_len / r; // len(P)/r

        /* P = sequence of strings (length of each = r) from 0 to n-1 */
        for (i = 0; i < n; i++) {
                concatenate(&P_i, &P[i * r/8], r, arr_of_zeros, c); // P_i || 0^c
                for (j = 0; j < b/8; j++) {
                        S_XOR[j] = S[j] ^ P_i[j]; // S XOR P_i || 0^c
                }
                /* Initially P_i was freed at the end of sponge function with the rest of the variables. However, according to Valgrind, that left a memory leak (I have no idea why though). Luckily, freeing P_i here in every iteration seems to fix the leak. */
                free(P_i);

                keccak_p(&S, S_XOR); // f(S XOR (P_i || 0^c))
        }

        while (1) {
                memcpy(S_Trunc_r, S, r/8);
                Z_len = concatenate(&Z, Z, Z_len, S_Trunc_r, r); // Z = Z || Trunc_r(S)
                if (d <= Z_len) {
                        memcpy((*output), Z, 256/8);
                        break;
                }
                memcpy(S_cpy, S, b/8);
                keccak_p(&S, S_cpy);
                // Continue with step 8
        }
        /* Free dynamically allocated memory */
        free(Z);
        free(P);
        free(padding);
}

/* Populate initial state array with input message
 * state_arr - pointer to state array placeholder
 * m - the input message
 */
void create_state_array(uint64_t (*state_arr)[5][5], const uint8_t *m) {
        uint32_t x, y, z, w=8, i;
        uint64_t lane;
        for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++) {
                        lane = 0;
                        for (z = 0; z < w; z++) {
                                i = w * (5 * y + x) + z;
                                lane += ROL64((uint64_t) m[i], z*8); // chars in m are 8-bit chunks. Rotate
                        }
                        // printf("lane[%d,%d]: %016llx\n", x,y,lane);
                        (*state_arr)[x][y] = lane; //i < m_len ? m[i] : 0;

                }
        }

}

/* Convert state array to string
 * s_dot - pointer to ouput string
 * state_arr - pointer to the state array
 */
void convert_state_arr_to_str(uint8_t *s_dot, uint64_t (*state_arr)[5][5]) {
        uint8_t i = 0, y, x, z;
        for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++) {
                        for (z = 0; z < 8; z++) {
                                s_dot[i] = (uint8_t) (ROL64((*state_arr)[x][y], 64 - z * 8) & (uint64_t) 255);
                                i++;
                        }
                }
        }
}

/* Do theta permutation
 * state_arr - pointer to the state array
 */
void theta(uint64_t (*state_arr)[5][5]) {
        int32_t x, y, z, w=64;
        uint64_t C[5],  D[5] = {0}, XOR;
        for (x = 0; x < 5; x++) {
                C[x] = (*state_arr)[x][0] ^ (*state_arr)[x][1] ^ (*state_arr)[x][2] ^ (*state_arr)[x][3] ^ (*state_arr)[x][4];
        }
        for (x = 0; x < 5; x++) {
                for (z = 0; z < w; z++) {
                        /* Attention! n % y returns negative int, if n < 0 and y > 0! Thus, add y to n to ensure proper behavior! */
                        XOR = ROL64(C[(x - 1 + 5) % 5], w - z) ^ ROL64(C[(x + 1 + 5) % 5], w - (z - 1 + w) % w);
                        XOR &= 1; // Apply bitmask to get only the value for current bit
                        D[x] += ROL64(XOR, z); // Shift XOR value to its proper place
                }
        }
        for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++) {
                        (*state_arr)[x][y] ^= D[x];
                }
        }
}

/* Do rho permutation
 * state_arr - pointer to the state array
 */
void rho(uint64_t (*state_arr)[5][5]) {
        uint8_t t, z, x = 1, y = 0, tmp, w = 64;
        uint64_t state_arr_cpy[5][5], curr_bit;
        memcpy(state_arr_cpy, *state_arr, sizeof(uint64_t) * 5 * 5);

        for (t = 0; t < 24; t++) {
                (*state_arr)[x][y] = 0; // let (x,y) = (1,0)
                for (z = 0; z < w; z++) {
                        /* Attention! n % y returns negative int, if n < 0 and y > 0! Thus, add y to n to ensure proper behavior! */
                        curr_bit = ROL64(state_arr_cpy[x][y], w - ((z - (t + 1)*(t + 2) / 2 + w) % w));
                        curr_bit &= 1; // Mask, to get only the curr_bit
                        curr_bit = ROL64(curr_bit, z);
                        (*state_arr)[x][y] += curr_bit;
                }
                /* let (x,y) = (y, (2x + 3y) mod 5) */
                tmp = x;
                x = y;
                y = (2*tmp + 3*y) % 5;
        }
}

/* Do pi permutation
 * state_arr - pointer to the state array
 */
void pi(uint64_t (*state_arr)[5][5]) {
        uint8_t x, y;
        uint64_t state_arr_cpy[5][5];
        memcpy(state_arr_cpy, *state_arr, sizeof(uint64_t) * 5 * 5);
        for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++) {
                        (*state_arr)[x][y] = state_arr_cpy[(x + 3 * y) % 5][x];
                }
        }
}

/* Do chi permutation
 * state_arr - pointer to the state array
 */
void chi(uint64_t (*state_arr)[5][5]) {
        uint8_t x, y, z, w = 64;
        uint64_t long_1 = 1; // Create 64 bit 1
        uint64_t first_term, second_term, third_term;
        uint64_t state_arr_cpy[5][5];
        memcpy(state_arr_cpy, *state_arr, sizeof(uint64_t) * 5 * 5);
        for (y = 0; y < 5; y++) {
                for (x = 0; x < 5; x++) {
                        (*state_arr)[x][y] = 0;
                        for (z = 0; z < w; z++) {
                                first_term = state_arr_cpy[x][y] & ROL64(long_1, z); // A[x,y,z]
                                second_term = (state_arr_cpy[(x+1)%5][y] & ROL64(long_1, z)) ^ ROL64(long_1, z); // A[(x+1) mod 5, y, z] XOR 1
                                third_term = state_arr_cpy[(x+2)%5][y] & ROL64(long_1, z); // A[(x+2) mod 5, y, z]
                                (*state_arr)[x][y] += first_term ^ (second_term & third_term);
                        }
                }
        }
}

/* Compute power for integers
 * uint32_t base - base
 * uint32_t exp - exponent
 * Returns base in the power of exponent
 */
uint32_t int_pow(uint32_t base, uint32_t exp) {
        uint32_t result = 1, i;
        for (i = 0; i < exp; i++) {
                result *= base;
        }
        return result;
}

/* Do iota permutation
 * state_arr - pointer to the state array
 * i_r - round index
 */
void iota(uint64_t (*state_arr)[5][5], uint32_t i_r) {
        uint32_t j, l = 6; // l = log2(w) = log2(64) = 6
        uint64_t RC = 0;
        for (j = 0; j <= l; j++) {
                RC += ROL64(rc(j + 7 * i_r), int_pow(2, j) - 1);
        }
        (*state_arr)[0][0] ^= RC;
}

/* Concatenate two bit strings (X||Y)
 *
 * Z   - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * X   - the first bit string
 * X_len - the length of the first string in bits
 * Y   - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
uint32_t concatenate(uint8_t **Z, const uint8_t *X,
                     uint32_t X_len, const uint8_t *Y,
                     uint32_t Y_len)
{
        /* The bit length of Z: the sum of X_len and Y_len */
        uint32_t Z_bit_len = X_len + Y_len;
        /* The byte length of Z:
         * the least multiple of 8 greater than X_len + Y_len */
        uint32_t Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
        // Allocate the output string and initialize it to 0
        *Z = calloc(Z_byte_len, sizeof(uint8_t));
        if (*Z == NULL)
                return 0;
        // Copy X_len/8 bytes from X to Z
        memcpy(*Z, X, X_len / 8);
        // Copy X_len%8 bits from X to Z
        for (uint32_t i = 0; i < X_len % 8; i++) {
                (*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
        }
        // Copy Y_len bits from Y to Z
        uint32_t Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
        uint32_t Y_byte_cursor = 0, Y_bit_cursor = 0;
        uint32_t v;
        for (uint32_t i = 0; i < Y_len; i++) {
                // Get the bit
                v = ((Y[Y_byte_cursor] >> Y_bit_cursor) & 1);
                // Set the bit
                (*Z)[Z_byte_cursor] |= (v << Z_bit_cursor);
                // Increment cursors
                if (++Y_bit_cursor == 8) {
                        Y_byte_cursor++;
                        Y_bit_cursor = 0;
                }
                if (++Z_bit_cursor == 8) {
                        Z_byte_cursor++;
                        Z_bit_cursor = 0;
                }
        }
        return Z_bit_len;
}

/* Concatenate the 01 bit string to a given bit string (X||01)
 *
 * Z   - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * X   - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
uint32_t concatenate_01(uint8_t **Z, const uint8_t *X,
                        uint32_t X_len)
{
        /* Due to the SHA-3 bit string representation convention, the 01
         * bit string is represented in hexadecimal as 0x02.
         * See Appendix B.1 of the Standard.
         */
        uint8_t zeroone[] = { 0x02 };
        return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *   caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
uint32_t pad10x1(uint8_t **P, uint32_t x, uint32_t m)
{
        /* 1. j = (-m-2) mod x */
        long j = x - ((m + 2) % x);
        /* 2. P = 1 || zeroes(j) || 1 */
        // Compute P bit and byte length
        uint32_t P_bit_len = 2 + j;
        uint32_t P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
        // Allocate P and initialize to 0
        *P = calloc(P_byte_len, sizeof(uint8_t));
        if (*P == NULL)
                return 0;
        // Set the 1st bit of P to 1
        (*P)[0] |= 1;
        // Set the last bit of P to 1
        (*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

        return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an uint8_t.
 */
uint8_t rc(uint32_t t)
{
        uint32_t tmod = t % 255;
        /* 1. If t mod255 = 0, return 1 */
        if (tmod == 0)
                return 1;
        /* 2. Let R = 10000000
         *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
        uint8_t R = 0x80, R0;
        /* 3. For i from 1 to t mod 255 */
        for (uint32_t i = 1; i <= tmod; i++) {
                /* a. R = 0 || R */
                R0 = 0;
                /* b. R[0] ^= R[8] */
                R0 ^= (R & 1);
                /* c. R[4] ^= R[8] */
                R ^= (R & 0x1) << 4;
                /* d. R[5] ^= R[8] */
                R ^= (R & 0x1) << 3;
                /* e. R[6] ^= R[8] */
                R ^= (R & 0x1) << 2;
                /* Shift right by one */
                R >>= 1;
                /* Copy the value of R0 in */
                R ^= R0 << 7;
        }
        /* 4. Return R[0] */
        return R >> 7;
}
