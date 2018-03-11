/* *********************************************************
    Design and implemented by Jiangfeng Sun
    Computer Science Department, New Mexico Tech.
    
    < This is the implementation of S-DES, taking
    a 8-bit plaintext/ciphertext & a 10-bit key as input,
    the output is the corresponding ciphertext/plaintext. >
********************************************************** */

#include"stdio.h"
#include"stdlib.h"
#include"string.h"

/* Print the usage information */
void print_usage(){
	printf("\nUsage: sdes [-e]/[-d] [text] [key]\n");
	printf("[text]: 8-bit {0, 1}\n");
	printf("[key]: 10-bit {0, 1}\n");
	printf("OPTION\n");
	printf("-e S-DES Encryption\n");
	printf("-d S-DES Decryption\n");
}

/* Generate the 2 subkeys */
char* K_Gen(char* key) {
	char k_shift1[] = {key[4], key[1], key[6], key[3], key[2], key[0], key[8], key[7], key[5], key[9], '\0'};
	char k_shift2[] = {key[6], key[3], key[2], key[4], key[1], key[7], key[5], key[9], key[0], key[8], '\0'};
	char k1[] = {key[0], key[6], key[8], key[3], key[7], key[2], key[9], key[5], '\0'};
	char k2[] = {key[7], key[2], key[5], key[4], key[9], key[1], key[8], key[0], '\0'};
	char K[] = {
		key[0], key[6], key[8], key[3], key[7], key[2], key[9], key[5],
		key[7], key[2], key[5], key[4], key[9], key[1], key[8], key[0], '\0'
	};
	char* temp = K;
	return temp;
}

/* Initial permutation */
char* IP(char* t) {
	char t_ip[] = {t[1], t[5], t[2], t[0], t[3], t[7], t[4], t[6], '\0'};
	char* temp = t_ip;
	return temp;
}

/* Inverse permutation */
char* inverse_IP(char* t) {
	char inverse_ip[] = {t[3], t[0], t[2], t[4], t[6], t[1], t[7], t[5], '\0'};
	char* temp = inverse_ip;
	return temp;
}

/* S-Boxs */
int sbox0[][4] = {
					1, 0, 3, 2,
					3, 2, 1, 0,
					0, 2, 1, 3,
					3, 1, 3, 2
};

int sbox1[][4] = {
					0, 1, 2, 3,
					2, 0, 1, 3,
					3, 0, 1, 0,
					2, 1, 0, 3
};

/* Function F, mapping the right 4-bit with a subkey, 
   generating a 4-bit output, which will be used by 
   another function fk */
char* mapping(char* text, char* subkey) {
	int t[8], SK[8];
	for(int i=0; i<8; i++){
		char temp1[2]= {text[i+4], '\0'};
		char temp2[2]= {subkey[i], '\0'};
		t[i] = atoi(temp1);
		SK[i] = atoi(temp2);
	}
	int result[8];
	result[0] = t[3] ^ SK[0]; result [1] = t[0] ^ SK[1];
	result[2] = t[1] ^ SK[2]; result [3] = t[2] ^ SK[3];
	result[4] = t[1] ^ SK[4]; result [5] = t[2] ^ SK[5];
	result[6] = t[3] ^ SK[6]; result [7] = t[0] ^ SK[7];
	int row1 = 2*result[0] + 1*result[3];
	int col1 = 2*result[1] + 1*result[2];
	int output1 = sbox0[row1][col1];
	int row2 = 2*result[4] + 1*result[7];
	int col2 = 2*result[5] + 1*result[6];
	int output2 = sbox1[row2][col2];
	char a, b, c, d;
	switch (output1){
		case 0: a = '0';
				b = '0';
				break;
		case 1: a = '0';
				b = '1';
				break;
		case 2: a = '1';
				b = '0';
				break;
		case 3: a = '1';
				b = '1';
				break;
		default: break;	
	}
	switch (output2){
		case 0: c = '0';
				d = '0';
				break;
		case 1: c = '0';
				d = '1';
				break;
		case 2: c = '1';
				d = '0';
				break;
		case 3: c = '1';
				d = '1';
				break;
		default: break;	
	}
	char P4[] = {b, d, c, a, '\0'};
	char* P = P4;
	return P;
}

/* Function fk, one input parameter is the output from function F,
   another parameter is a subkey, generating a 8-bit output */
char* fk(char* t, char* subkey) {
	char left[] = {t[0], t[1], t[2], t[3], '\0'};
	char right[] = {t[4], t[5], t[6], t[7], '\0'};
	char* r = mapping(t, subkey);
	char temp_r[] = {r[0], r[1], r[2], r[3], '\0'};
	int i[4], j[4];
	for(int n=0; n<4; n++){
		char temp1[2]= {left[n], '\0'};
		char temp2[2]= {temp_r[n], '\0'};
		i[n] = atoi(temp1);
		j[n] = atoi(temp2);
	}
	int k[4];
	k[0] = i[0] ^ j[0]; k[1] = i[1] ^ j[1];
	k[2] = i[2] ^ j[2]; k[3] = i[3] ^ j[3];
	char new_left[4];	
	for(int n=0; n<4; n++){
		switch (k[n]){
		case 0: new_left[n] = '0';				
				break;
		case 1: new_left[n] = '1';				
				break;
		default: break;				
		}
	}	
	char result[] = {
		new_left[0], new_left[1], new_left[2], new_left[3], 
		right[0], right[1], right[2], right[3], '\0'};
	char* temp = result;
	return temp;
}

/* Swap function, switch the position of left 4-bit with right 4-bit */
char* SW(char* a) {
	char c[] = {a[4], a[5], a[6], a[7], a[0], a[1], a[2], a[3]};
	char* temp = c;
	return temp;
}

/* Encryption */
void encrypt(char* plaintext, char* key){
	char* K = K_Gen(key);
	char SK1[] = {K[0], K[1], K[2], K[3], K[4], K[5], K[6], K[7], '\0'};
	char SK2[] = {K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], '\0'};
	char* c = inverse_IP(fk(SW(fk(IP(plaintext), SK1)),SK2));
	char ciphertext[] = {c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], '\0'};
	printf("Ciphertext: %s\n", ciphertext);
}

/* Decryption */
char* decrypt(char* ciphertext, char* key){
	char* K = K_Gen(key);
	char SK1[] = {K[0], K[1], K[2], K[3], K[4], K[5], K[6], K[7], '\0'};
	char SK2[] = {K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], '\0'};
	char* p = inverse_IP(fk(SW(fk(IP(ciphertext), SK2)),SK1));
	char plaintext[] = {p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], '\0'};
	printf("Plaintext: %s\n", plaintext);
}

/* Check validation of input parameters */
int check(int argc, char* argv1, char* argv2, char* argv3) {
	int result = 1;
	if (argc!=4||argv1[0]!='-'||strlen(argv1)!=2||strlen(argv2)!=8||strlen(argv3)!=10){
		printf("Something wrong with the inputs, see usage below:\n");
		print_usage();
		result = 0;
		return result;
	}
	else {
		for (int i=0; i<strlen(argv2); i++) {
			if (argv2[i] != '0' && argv2[i] != '1') {
			printf("Something wrong with the inputs, see usage below:\n");
			print_usage();
			result = 0;
			return result;
			}
		}
		for (int j=0; j<strlen(argv3); j++) {
			if (argv3[j] != '0' && argv3[j] != '1') {
			printf("Something wrong with the inputs, see usage below:\n");
			print_usage();
			result = 0;
			return result;
			}
		}
		return result;
	}	
}

/* Main function starts here */
int main(int argc, char* argv[]){
	if (!check(argc, argv[1], argv[2], argv[3]))
		return 0;
	else {
		switch (argv[1][1]) {
		case 'e':
			encrypt(argv[2], argv[3]);
			break;
		case 'd':
			decrypt(argv[2], argv[3]);
			break;
		default:
			print_usage();
			return 0;
		}
		return 1;
	}	
}
