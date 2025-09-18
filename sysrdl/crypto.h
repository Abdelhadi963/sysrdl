#pragma once
#include <stdio.h>
#include <string.h>

#define N 256

/*Initialization function */
void rc4_init(unsigned char *state, unsigned char *key, unsigned long len) 
{
	int i, j = 0;
	char k[N] = { 0 };
	unsigned char temp = 0;
	for (i = 0; i < N; i++) 
	{
		k[i] = key[i % len];
		state[i] = i;
	}
	for (i = 0; i < N; i++) 
	{
		j = (j + state[i] + k[i]) % N;

		// swap state[i] and state[j]
		temp = state[i];
		state[i] = state[j];
		state[j] = temp;
	}

}

/*Encryption & Decryption function*/
void rc4_crypt(unsigned char *state, unsigned char *Data, unsigned long len)
{
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char temp;

	for (k = 0; k < len; k++) 
	{
		i = (i + 1) % N;
		j = (j + state[i]) % N;
		// swap state[i] and state[j]
		temp = state[i];
		state[i] = state[j];
		state[j] = temp;
		t = (state[i] + state[j]) % N;
		Data[k] ^= state[t];
	}
}
