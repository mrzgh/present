/*
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *  a simple PRESENT implementation
 *  functions file present.h
 *	by: Muhammad Reza Z'aba,
 *		Information Security Institute
 *		Queensland University of Technology
 *
 * version: 100907
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

#include <stdio.h>
#define pf printf
#define fpf fprintf
#define u32 unsigned int           // holds 32-bit values
#define u16 unsigned short int     // holds 16-bit values
#define u8 unsigned char           // holds 8-bit values
#define s8 signed char
#define ROUNDS 31                        // round number

void pfa(u32 *a, u8 size, u8 flag);

void pfa64(u32 a[][4], u8 size, u8 flag);

void pfa128(u32 a[][4], u8 size, u8 flag);


void keySchedule(u16 *key, u16 K[][4], u16 keySize);

void encrypt(u16 K[][4], u16 *B);

void decrypt(u16 K[][4], u16 *B);

void Round(u16 *key, u16 *B);

void RoundInv(u16 *key, u16 *B);

void addRoundKey(u16 *key, u16 *X);

void sBoxlayer(u16 *X);

void sBoxlayerInv(u16 *X);

void pLayer(u16 *X);

void pLayerInv(u16 *X);

u32 ROT32L(u32 a, u8 n);

u32 ROT32R(u32 a, u8 n);
