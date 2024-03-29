#include <stdint.h>
/* Implement the following API. Do NOT modify the given prototypes. */

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer (allocated by the caller)
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
 void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
 	  unsigned int l);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */



/* Implement KECCAK-p[b,n_r](S)
 * m - input string of length b
 * S - pointer to KECCAK-modified string
 */
void keccak_p(uint8_t (*S)[200], uint8_t *m);

/* Implement SPONGE construct to truncate/pad the input string to an output string of
* length d
* output - pointer to output string
* N - pointer to input string
* d - length of output string (in bits)
* l - length of N in bits
*/
void sponge(uint8_t **output, uint8_t *N, uint32_t d, int32_t l);

/* Populate initial state array with input message
 * state_arr - pointer to state array placeholder
 * m - the input message
 */
void create_state_array(uint64_t (*state_arr)[5][5], const uint8_t *m);

/* Convert state array to string
* s_dot - pointer to ouput string
* state_arr - pointer to the state array
*/
void convert_state_arr_to_str(uint8_t *s_dot, uint64_t (*state_arr)[5][5]);

/* Do theta permutation
 * state_arr - pointer to the state array
 */
void theta(uint64_t (*state_arr)[5][5]);

/* Do rho permutation
 * state_arr - pointer to the state array
 */
void rho(uint64_t (*state_arr)[5][5]);

/* Do pi permutation
 * state_arr - pointer to the state array
 */
void pi(uint64_t (*state_arr)[5][5]);

/* Do chi permutation
 * state_arr - pointer to the state array
 */
void chi(uint64_t (*state_arr)[5][5]);

/* Compute power for integers
 * uint32_t base - base
 * uint32_t exp - exponent
 * Returns base in the power of exponent
 */
uint32_t int_pow(uint32_t base, uint32_t exp);

/* Do iota permutation
 * state_arr - pointer to the state array
 * i_r - round index
 */
void iota(uint64_t (*state_arr)[5][5], uint32_t i_r);
