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
 
/* Populate initial state array with input message
 * state_arr - pointer to state array placeholder
 * m - the input message
 */
void create_state_array(unsigned char (*state_arr)[5][5][1600/25/8], const unsigned char *m);

/* Do one iteration of the Rnd function
 * state_arr - pointer to state array
 * i_r - round index
 */
void rnd_fun(unsigned char (*state_arr)[5][5][1600/25/8], unsigned char i_r);

/* Do theta permutation
 * state_arr - state array
 */
void theta(unsigned char (*state_arr)[5][5][1600/25/8]);

/* Do rho permutation
 * state_arr - state array
 */
void rho(unsigned char (*state_arr)[5][5][1600/25/8]);

/* Do pi permutation
 * state_arr - state array
 */
void pi(unsigned char (*state_arr)[5][5][1600/25/8]);

/* Do chi permutation
 * state_arr - state array
 */
void chi(unsigned char (*state_arr)[5][5][1600/25/8]);

/* Do iota permutation
 * state_arr - state array
 * i_r - round index
 */
void iota(unsigned char (*state_arr)[5][5][1600/25/8], int i_r);

/* Convert state array to string
 * s_dot - pointer to ouput string
 * state_arr - state array
 */
 void convert_state_arr_to_str(unsigned char *s_dot, unsigned char (*state_arr)[5][5][1600/25/8]);
 
 /* Implement SPONGE construct to truncate/pad the input string to an output string of
  * length d
  * Z - pointer output string
  * d - length of output string (in bits)
  * N - input string
  */
 void sponge(unsigned char *Z, unsigned int d, unsigned char *N);
