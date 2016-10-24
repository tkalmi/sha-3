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
void keccak_p(unsigned char (*S)[200], unsigned char *m);

/* Implement SPONGE construct to truncate/pad the input string to an output string of
* length d
* Z - pointer to output string
* N - pointer to input string
* d - length of output string (in bits)
* l - length of N in bits
*/
void sponge(unsigned char **Z, unsigned char *N, unsigned int d, int l);

/* Populate initial state array with input message
 * state_arr - pointer to state array placeholder
 * m - the input message
 */
void create_state_array(unsigned long long (*state_arr)[5][5], const unsigned char *m);

/* Convert state array to string
* s_dot - pointer to ouput string
* state_arr - pointer to the state array
*/
void convert_state_arr_to_str(unsigned char *s_dot, unsigned long long (*state_arr)[5][5]);

/* Do theta permutation
 * state_arr - pointer to the state array
 */
void theta(unsigned long long (*state_arr)[5][5]);

/* Do rho permutation
 * state_arr - pointer to the state array
 */
void rho(unsigned long long (*state_arr)[5][5]);

/* Do pi permutation
 * state_arr - pointer to the state array
 */
void pi(unsigned long long (*state_arr)[5][5]);

/* Do chi permutation
 * state_arr - pointer to the state array
 */
void chi(unsigned long long (*state_arr)[5][5]);

/* Compute power for integers
 * int n - base
 * int x - exponent
 * return - pow(base, result)
 */
int int_pow(int n, int x);

/* Do iota permutation
 * state_arr - pointer to the state array
 * i_r - round index
 */
void iota(unsigned long long (*state_arr)[5][5], int i_r);
