#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "sha3.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);
unsigned char rc(unsigned int t);

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l)
{
	/* The hash size must be one of the supported ones */
	if (s != 224 && s != 256 && s != 384 && s != 512)
		return;

	/* Implement the rest of this function */
	/* We'll implement only the SHA3-256, with width 1600 and round number 24 for now... */
	/*
		TODO: Implement SPONGE
		TODO: Profit?
	 */
	 int w = 8, w_log = 6; // w_log is the 'l' in documentation w_log = log2(w) = log2(64) = 6
	 unsigned long state_arr[5][5]; // Initialize state array. It consists of 1600 bits in the format of 5 * 5 (=25) lanes. That makes the length of each lane 1600/25 bits (=8 bytes). As the input msg is in bytes, we'll use that format. 
	 
	 create_state_array(&state_arr, m); // Populate initial state array with input message
	 
	 /* n_r - Number of Rnd-function iterations
	  * i_r - Round index
	  */
	 int n_r = 24, i_r, ii, jj;
	 printf("Message: %s\n", m);
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
	 for (i_r = 12 + 2*w_log - n_r; i_r < 12 + 2*w_log - 1; i_r++) {
	 	printf("\n-- ROUND %d --\n", i_r);
		theta(&state_arr);
		printf("\nAfter theta:\n");
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
		rho(&state_arr);
		printf("\nAfter rho:\n");
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
		pi(&state_arr);
		printf("\nAfter pi:\n");
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
		chi(&state_arr);
		printf("\nAfter chi:\n");
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
		iota(&state_arr, i_r);
		printf("\nAfter iota:\n");
		 for (ii = 0; ii < 5; ii++) {
		 	for (jj = 0; jj < 5; jj++) {
		 			printf("%016lx ",state_arr[ii][jj]);
		 	}
		 	printf("\n");
		 }
	 }
	 
	 unsigned char s_dot[5 * 5 * w];
	 convert_state_arr_to_str(s_dot, &state_arr);
	 sponge(d, s, s_dot);
	 (void) l;
}

/* Implement SPONGE construct to truncate/pad the input string to an output string of
 * length d
 * Z - pointer output string
 * d - length of output string (in bits)
 * N - input string
 */
void sponge(unsigned char *Z, unsigned int d, unsigned char *N) {
	//unsigned char *padded;
	//pad10x1(*padded, N, strlen(N));
	//concatenate(*Z, N, strlen(N) * 8, padded, strlen(padded) * 8);
	(void)Z;(void)d;(void)N;
}

/* Populate initial state array with input message
 * state_arr - pointer to state array placeholder
 * m - the input message
 */
void create_state_array(unsigned long (*state_arr)[5][5], const unsigned char *m) {
	unsigned int x, y, z, w=8, i, m_len=strlen((const char *)m);
	unsigned long lane;
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			lane = 0;
			for (z = 0; z < w; z++) {
				i = w * (5 * y + x);
				lane += i < m_len ? ROL64(m[i], z*8) : 0; // chars in m are 8-bit chunks
			}
			(*state_arr)[x][y] = lane; //i < m_len ? m[i] : 0;
			
		}
	}
	
}

/* Convert state array to string
 * s_dot - pointer to ouput string
 * state_arr - pointer to state array
 */
 void convert_state_arr_to_str(unsigned char *s_dot, unsigned long (*state_arr)[5][5]) {
 	unsigned char i = 0, y, x;
 	for (y = 0; y < 5; y++) {
 		for (x = 0; x < 5; x++) {
			s_dot[i] = (*state_arr)[x][y];
			i++;
 		}
 	}
 }

/* Do theta permutation
 * state_arr - pointer to state array
 */
void theta(unsigned long (*state_arr)[5][5]) {
	int x, y, z, w=64;
	unsigned long C[5],  D[5] = {0}, XOR;
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
 * state_arr - pointer to state array
 */
void rho(unsigned long (*state_arr)[5][5]) {
	unsigned char t, z, x = 1, y = 0, tmp, w = 64;
	unsigned long state_arr_cpy[5][5], curr_bit;
	memcpy(state_arr_cpy, *state_arr, sizeof(unsigned long) * 5 * 5);
	(*state_arr)[x][y] = 0; // let (x,y) = (1,0)
	for (t = 0; t < 24; t++) {
		for (z = 0; z < w; z++) {
			/* Attention! n % y returns negative int, if n < 0 and y > 0! Thus, add y to n to ensure proper behavior! */
			curr_bit = state_arr_cpy[x][y] & (unsigned long ) 1 << ((z - (t + 1)*(t + 2) / 2 + w) % w); // Mask, to get only the curr_bit 
			(*state_arr)[x][y] += curr_bit;
			/* let (x,y) = (y, (2x + 3y) mod 5) */
			tmp = x;
			x = y;
			y = (2*tmp + 3*y) % 5;
		}
	}
}

/* Do pi permutation
 * state_arr - pointer to state array
 */
void pi(unsigned long (*state_arr)[5][5]) {
	unsigned char x, y;
	unsigned long state_arr_cpy[5][5];
	memcpy(state_arr_cpy, *state_arr, sizeof(unsigned long) * 5 * 5);
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
				(*state_arr)[x][y] = state_arr_cpy[(x + 3 * y) % 5][x];
		}
	}
}

/* Do chi permutation
 * state_arr - pointer to state array
 */
void chi(unsigned long (*state_arr)[5][5]) {
	unsigned char x, y;
	unsigned long state_arr_cpy[5][5];
	memcpy(state_arr_cpy, *state_arr, sizeof(unsigned long) * 5 * 5);
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
				(*state_arr)[x][y] = state_arr_cpy[x][y] ^ ((state_arr_cpy[(x+1)%5][y] ^ 1) * state_arr_cpy[(x+2)%5][y]);
		}
	}
}

/* Compute power for integers
 * int n - base
 * int x - exponent
 */
int int_pow(int n, int x) {
	int result = 1;
	for (int i = 0; i < x; i++) {
		result *= n;
	}
	return result;
}

/* Do iota permutation
 * state_arr - pointer to state array
 * i_r - round index
 */
void iota(unsigned long (*state_arr)[5][5], int i_r) {
	int j, l = 6; // l = log2(w) = log2(64) = 6
	unsigned long RC = 0;
	//printf("i_r: %d\n", i_r);
	for (j = 0; j < l; j++) {
		//printf("j: %d -> rc(%d): %0x", j, j+7*i_r, rc(j + 7 * i_r));
		RC += ROL64(rc(j + 7 * i_r), int_pow(2, j) - 1);
		//printf(" -> RC + %ld %ld\n", (unsigned long)int_pow(2, int_pow(2,j) - 1) * rc(j + 7 * i_r), RC);
	}
	//printf("\nRC: %016lx \n", RC);
	(*state_arr)[0][0] ^= RC;
} 

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len)
{
	/* The bit length of Z: the sum of X_len and Y_len */
	unsigned long Z_bit_len = X_len + Y_len;
	/* The byte length of Z:
	 * the least multiple of 8 greater than X_len + Y_len */
	unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
	// Allocate the output string and initialize it to 0
	*Z = calloc(Z_byte_len, sizeof(unsigned char));
	if (*Z == NULL)
		return 0;
	// Copy X_len/8 bytes from X to Z
	memcpy(*Z, X, X_len / 8);
	// Copy X_len%8 bits from X to Z
	for (unsigned int i = 0; i < X_len % 8; i++) {
		(*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
	}
	// Copy Y_len bits from Y to Z
	unsigned long Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
	unsigned long Y_byte_cursor = 0, Y_bit_cursor = 0;
	unsigned int v;
	for (unsigned long i = 0; i < Y_len; i++) {
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
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len)
{
	/* Due to the SHA-3 bit string representation convention, the 01
	 * bit string is represented in hexadecimal as 0x02.
	 * See Appendix B.1 of the Standard.
	 */
	unsigned char zeroone[] = { 0x02 };
	return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
	/* 1. j = (-m-2) mod x */
	long j = x - ((m + 2) % x);
	/* 2. P = 1 || zeroes(j) || 1 */
	// Compute P bit and byte length
	unsigned long P_bit_len = 2 + j;
	unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
	// Allocate P and initialize to 0
	*P = calloc(P_byte_len, sizeof(unsigned char));
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
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
	unsigned int tmod = t % 255;
	/* 1. If t mod255 = 0, return 1 */
	if (tmod == 0)
		return 1;
	/* 2. Let R = 10000000
	 *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
	unsigned char R = 0x80, R0;
	/* 3. For i from 1 to t mod 255 */
	for (unsigned int i = 1; i <= tmod; i++) {
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
