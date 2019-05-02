/*
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *  a simple PRESENT implementation
 *  functions file present.c
 *  This code is written for clarity to the human reader and thus, not optimized
 *  for speed.
 *	by: Muhammad Reza Z'aba,
 *		Information Security Institute
 *		Queensland University of Technology
 *
 * version: 100907
 *=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

#include "present.h"

u8 S[16] = { 0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 
             0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2 };

u8 SInv[16] = { 0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 
                0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA };

void pfa128(u32 a[][4], u8 size, u8 flag) {
     u8 i, j;
     
     if (flag == 1) {
         for (i=0; i<size; i++) {
            pf("%08X %08X %08X %08X\n", a[i][0], a[i][1], a[i][2], a[i][3]);
         }
         pf("\n");
     }
     else {
         for (i=0; i<size; i++)
             for (j=0; j<4; j++)
                 pf("%08X ", a[i][j]);
         pf("\n");
     }
}

/*
 *  To print 32-bit KEYSIZE-dimension arrays (64 bits)
 */
void pfa64(u32 a[][4], u8 size, u8 flag) {
     u8 i, j;
     
     if (flag == 1) {
         for (i=0; i<size; i++) {
            pf("%08X %08X\n", a[i][0], a[i][1]);
         }
         pf("\n");
     }
     else {
         for (i=0; i<size; i++)
             for (j=0; j<2; j++)
                 pf("%08X ", a[i][j]);
         pf("\n");
     }
}

/*
 *  To print 32-bit arrays
 */
void pfa(u32 *a, u8 size, u8 flag) {
    u8 i;
     
    if (flag == 1) {
        for (i=0; i<size; i++) {
            pf("%08X ", a[i]);
            if (i%2 == 1)
                pf("\n");
        }
        pf("\n");
    }
    else {
        for (i=0; i<size; i++)
            pf("%08X ", a[i]);
        pf("\n");
    }
}

/*
 * Key schedule
 */
void keySchedule(u16 *key, u16 K[][4], u16 keySize) {
    u16 keyReg[8]; // support for 128-bit key
    u16 temp[8];
    u8 i, j, s;
    
    for (i = 0; i < 8; i++) {
        keyReg[i] = key[i];
    }
    
    K[0][0] = keyReg[0];
    K[0][1] = keyReg[1];
    K[0][2] = keyReg[2];
    K[0][3] = keyReg[3];
    
    pf("K 1: %04X %04X %04X %04X\n", keyReg[0], keyReg[1], keyReg[2], \
        keyReg[3]);

    for (i = 2; i <= 32; i++) {
        //temp[0] = temp[1] = temp[2] = temp[3] = temp[4] = 0;
        
        // rotating 61 bits to the left
        temp[0] = ((keyReg[3] & 0x0007) << 13) | (keyReg[4] >> 3);
        temp[1] = ((keyReg[4] & 0x0007) << 13) | (keyReg[0] >> 3);
        temp[2] = ((keyReg[0] & 0x0007) << 13) | (keyReg[1] >> 3);
        temp[3] = ((keyReg[1] & 0x0007) << 13) | (keyReg[2] >> 3);
        temp[4] = ((keyReg[2] & 0x0007) << 13) | (keyReg[3] >> 3);
        
        for (j = 0; j < 5; j++) {
            keyReg[j] = temp[j];
        }
        pf("  Rotate: %04X %04X %04X %04X %04X\n", keyReg[0], keyReg[1], keyReg[2], \
            keyReg[3], keyReg[4]);
        
        // sbox
        s = S[keyReg[0] >> 12];
        keyReg[0] &= 0x0FFF;
        keyReg[0] |= (s << 12);
        
        pf("  Sbox:   %04X %04X %04X %04X %04X\n", keyReg[0], keyReg[1], keyReg[2], \
            keyReg[3], keyReg[4]);
        
        // XOR with round counter i
        pf("  Round counter: %X\n", i-1);
        keyReg[4] ^= ((i-1) << 15);
        keyReg[3] ^= ((i-1) >> 1);
        
        pf("  XOR:    %04X %04X %04X %04X %04X\n\n", keyReg[0], keyReg[1], keyReg[2], \
            keyReg[3], keyReg[4]);
        
        K[i - 1][0] = keyReg[0];
        K[i - 1][1] = keyReg[1];
        K[i - 1][2] = keyReg[2];
        K[i - 1][3] = keyReg[3];

        pf("K%2d: %04X %04X %04X %04X\n", i, keyReg[0], keyReg[1], keyReg[2], \
            keyReg[3]);
    }
    
    //*
    pf("Encryption keys: \n");
    for (i = 0; i < 32; i++) {
        pf("%8X %8X %8X %8X\n", K[i][0], K[i][1], K[i][2], K[i][3]);
    }
    
    /*
    pf("Decryption keys: \n");
    for (i = 0; i < 33; i++) {
        pf("%8X %8X %8X %8X\n", K->Dec[i][0], K->Dec[i][1], K->Dec[i][2], \
            K->Dec[i][3]);
    }
    */
}
    
void encrypt(u16 K[][4], u16 *X) {
    u16 subkey[4];
    u8 i;
    
    for (i = 1; i <= 31; i++) {
        subkey[0] = K[i - 1][0];
        subkey[1] = K[i - 1][1];
        subkey[2] = K[i - 1][2];
        subkey[3] = K[i - 1][3];
        Round(subkey, X);
    }
    subkey[0] = K[i - 1][0];
    subkey[1] = K[i - 1][1];
    subkey[2] = K[i - 1][2];
    subkey[3] = K[i - 1][3];
    addRoundKey(subkey, X);
    
    //pf("R%2d %8X %8X %8X %8X\n", i, B[0], B[1], B[2], B[3]);
}

void decrypt(u16 K[][4], u16 *X) {
    u16 subkey[4];
    s8 i;
    
    subkey[0] = K[31][0];
    subkey[1] = K[31][1];
    subkey[2] = K[31][2];
    subkey[3] = K[31][3];
    addRoundKey(subkey, X);
    for (i = 31; i >= 1; i--) {
        subkey[0] = K[i - 1][0];
        subkey[1] = K[i - 1][1];
        subkey[2] = K[i - 1][2];
        subkey[3] = K[i - 1][3];
        RoundInv(subkey, X);
    }
}

void Round(u16 *key, u16 *X) {
    addRoundKey(key, X);
    sBoxlayer(X);
    pLayer(X);
}

void RoundInv(u16 *key, u16 *X) {
    pLayerInv(X);
    sBoxlayerInv(X);
    addRoundKey(key, X);      
}

void addRoundKey(u16 *key, u16 *X) {
    u8 i;
    
    for (i = 0; i < 4; i++) {
        X[i] ^= key[i];
    }
}

void sBoxlayer(u16 *X) {
    u8 output[4][4];
    u8 i, j, input;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            input = (X[i] >> (j * 4)) & 0x000F;
            output[i][j] = S[input];
        }
    }
    
    for (i = 0; i < 4; i++) {
        X[i] = 0;
        for (j = 0; j < 4; j++) {
            X[i] |= (output[i][j] << (j * 4));
        }
    }
}

void sBoxlayerInv(u16 *X) {
    u8 output[4][4];
    u8 i, j, input;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            input = (X[i] >> (j * 4)) & 0x000F;
            output[i][j] = SInv[input];
        }
    }
    
    for (i = 0; i < 4; i++) {
        X[i] = 0;
        for (j = 0; j < 4; j++) {
            X[i] |= (output[i][j] << (j * 4));
        }
    }
}

void pLayer(u16 *X) {
    u8 y[16] = { 0 };
    u8 i, j;
    
    for (i = 0; i < 4; i++) {
        y[i] |= ((X[i] & 0x8000) >> 12);
        y[i] |= ((X[i] & 0x0800) >> 9);
        y[i] |= ((X[i] & 0x0080) >> 6);
        y[i] |= ((X[i] & 0x0008) >> 3);
    }
    
    for (i = 0; i < 4; i++) {
        y[i + 4] |= ((X[i] & 0x4000) >> 11);
        y[i + 4] |= ((X[i] & 0x0400) >> 8);
        y[i + 4] |= ((X[i] & 0x0040) >> 5);
        y[i + 4] |= ((X[i] & 0x0004) >> 2);
    }
    
    for (i = 0; i < 4; i++) {
        y[i + 8] |= ((X[i] & 0x2000) >> 10);
        y[i + 8] |= ((X[i] & 0x0200) >> 7);
        y[i + 8] |= ((X[i] & 0x0020) >> 4);
        y[i + 8] |= ((X[i] & 0x0002) >> 1);
    }
    
    for (i = 0; i < 4; i++) {
        y[i + 12] |= ((X[i] & 0x1000) >> 9);
        y[i + 12] |= ((X[i] & 0x0100) >> 6);
        y[i + 12] |= ((X[i] & 0x0010) >> 3);
        y[i + 12] |= ((X[i] & 0x0001) >> 0);
    }
    
    for (i = 0; i < 4; i++) {
        X[i] = 0;
        for (j = 0; j < 4; j++) {
            X[i] |= (y[i * 4 + j] << (12 - j * 4));
        }
    }
}

void pLayerInv(u16 *X) {
    u16 y[4] = { 0 };
    u8 i;
    
    for (i = 0; i < 4; i++) {
        // to sbox 15
        y[i] |= (((X[0] & (0x8000 >> i * 4)) >> (15 - i * 4)) << 15);
        y[i] |= (((X[1] & (0x8000 >> i * 4)) >> (15 - i * 4)) << 14);
        y[i] |= (((X[2] & (0x8000 >> i * 4)) >> (15 - i * 4)) << 13);
        y[i] |= (((X[3] & (0x8000 >> i * 4)) >> (15 - i * 4)) << 12);
        
        // to sbox 14
        y[i] |= (((X[0] & (0x4000 >> i * 4)) >> (14 - i * 4)) << 11);
        y[i] |= (((X[1] & (0x4000 >> i * 4)) >> (14 - i * 4)) << 10);
        y[i] |= (((X[2] & (0x4000 >> i * 4)) >> (14 - i * 4)) << 9);
        y[i] |= (((X[3] & (0x4000 >> i * 4)) >> (14 - i * 4)) << 8);
        
        // to sbox 13
        y[i] |= (((X[0] & (0x2000 >> i * 4)) >> (13 - i * 4)) << 7);
        y[i] |= (((X[1] & (0x2000 >> i * 4)) >> (13 - i * 4)) << 6);
        y[i] |= (((X[2] & (0x2000 >> i * 4)) >> (13 - i * 4)) << 5);
        y[i] |= (((X[3] & (0x2000 >> i * 4)) >> (13 - i * 4)) << 4);
        
        // to sbox 12
        y[i] |= (((X[0] & (0x1000 >> i * 4)) >> (12 - i * 4)) << 3);
        y[i] |= (((X[1] & (0x1000 >> i * 4)) >> (12 - i * 4)) << 2);
        y[i] |= (((X[2] & (0x1000 >> i * 4)) >> (12 - i * 4)) << 1);
        y[i] |= (((X[3] & (0x1000 >> i * 4)) >> (12 - i * 4)) << 0);     
    }
    
    for (i = 0; i < 4; i++) {
        X[i] = y[i];
    }
    
}

u32 ROT32L(u32 a, u8 n) {
    return (a << n) | (a >> (32 - n));
}

u32 ROT32R(u32 a, u8 n) {
    return (a >> n) | (a << (32 - n));
}
