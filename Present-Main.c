/*
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *  PRESENT test vectors
 *  functions file present.c
 *	by: Muhammad Reza Z'aba,
 *		Information Security Institute
 *		Queensland University of Technology
 *
 * version: 100907
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

#include "present.h"
#include "rngs.h"
#include <time.h>
#define MAXRANDOM 2147483647


void initialTest();
void testingKeyDifference();

int main(int argc, char *argv[]) {

	initialTest();
	//testingKeyDifference();

    return 0;
}

void initialTest() {
    u16 key[5] = { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 };
    //u16 p[4] = { 0x0000, 0x0000, 0x0000, 0x0000 };
    u16 p[4] = { 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF };
    u16 c[4];
    u32 i;
    u8 j, k;
    u16 keySize;
    u16 K[ROUNDS+1][4];
    u32 ITERATION;
    clock_t t1;
    
    keySize = 128;
    keySchedule(key, K, keySize);
    
    pf("K: ");
    for (i = 0; i < keySize / 16; i++) {
        pf("%04X ", key[i]);
    }
    pf("\n");
    pf("P: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
    encrypt(K, p);
    pf("C: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
    
    decrypt(K, p);
    pf("P: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
    
    // test sBoxLayer
    p[0] = p[1] = p[2] = p[3];
    sBoxlayer(p);
    pf("sbox: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
    
    // test pLayer
    p[0] = p[1] = p[2] = p[3] = 0x4444;
    pLayer(p);
    pf("pLayer: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
    
    /*
     * Random number initialization for random test vectors testing
     */
    SelectStream(0);
    PlantSeeds(-1);
    
    t1 = clock();
    ITERATION = 0;
    pf("Performing %d test vectors... ", ITERATION);
    for (i = 0; i < ITERATION; i++) {
        for (j = 0; j < 4; j++) {
            p[j] = MAXRANDOM * Random();
            key[j] = MAXRANDOM * Random();
        }
        key[j] = MAXRANDOM * Random();
        
        keySchedule(key, K, keySize);
        for (j = 0; j < 4; j++) {
            c[j] = p[j];
        }
        //pf("P: %04X %04X %04X %04X\n", p[0], p[1], p[2], p[3]);
        encrypt(K, c);
        //pf("C: %04X %04X %04X %04X\n", c[0], c[1], c[2], c[3]);
        decrypt(K, c);
        
        if ((c[0] != p[0]) | (c[1] != p[1]) | (c[2] != p[2]) | (c[3] != p[3])) {
            pf("haha %d ", i);
        }
    }
    pf("Done! \n");
    pf("\n[%f seconds]\n", (clock() - t1) / (double) CLOCKS_PER_SEC);
    
    //system("PAUSE");

}

void testingKeyDifference() {
    u16 key1[5] = { 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 };
    u16 key2[5] = { 0x8000, 0x0000, 0x0000, 0x0000, 0x0000 };
    u32 i, j;
    u16 keySize;
    u16 K1[ROUNDS+1][4];
    u16 K2[ROUNDS+1][4];

    keySize = 80;
    keySchedule(key1, K1, keySize);
    keySchedule(key2, K2, keySize);

    for (i=0; i<ROUNDS+1; i++) {
    	for (j=0; j<4; j++) {
    		if ((K1[i][j] ^ K2[i][j])==0)
    			pf(".... ");
    		else
    			pf("%04X ", K1[i][j] ^ K2[i][j]);
    	}
    	pf("\n");
    }

}
