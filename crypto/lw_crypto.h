/**************************************************************************
 Copyright (c) <2016> <Jiapeng Li>
 https://github.com/JiapengLi/lorawan-parser

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.

*****************************************************************************/
#include <stdbool.h>

#ifndef DRV_LOBAWAN_LW_CRYPTO_H_
#define DRV_LOBAWAN_LW_CRYPTO_H_

typedef union{
    uint32_t data;
    uint8_t buf[4];
    struct{
    #ifdef ENABLE_BIG_ENDIAN
        uint32_t nwkaddr        : 25;
        uint32_t nwkid          : 7;
    #else
        uint32_t nwkid          : 7;
        uint32_t nwkaddr        : 25;
    #endif
    }bits;
}__attribute__((packed)) lw_devaddr_t;

typedef union{
    uint32_t data;
    uint8_t buf[4];
}__attribute__((packed)) lw_mic_t;

typedef enum{
    LW_UPLINK = 0,
    LW_DOWNLINK = 1,
}lw_link_t;

typedef union{
    uint32_t data;
}__attribute__((packed))  lw_anonce_t;

typedef union{
    uint16_t data;
}__attribute__((packed)) lw_dnonce_t;

typedef lw_anonce_t lw_netid_t;

typedef struct{
    uint8_t *aeskey;
    lw_anonce_t anonce;
    lw_netid_t netid;
    lw_dnonce_t dnonce;
}lw_skey_seed_t;

typedef struct{
    uint8_t *nwkkey;
    uint8_t *appkey;
    lw_anonce_t jnonce;
    uint8_t *joineui;
    lw_dnonce_t dnonce;
}lw_skey_seed_11_t;

typedef struct{
    uint8_t *aeskey;
    const uint8_t *in;
    uint16_t len;
    lw_devaddr_t devaddr;
    lw_link_t link;
    uint32_t fcnt32;
}lw_key_t;

typedef struct{
    uint8_t *snwksintkey;
    uint8_t *fnwksintkey;
    uint8_t *in;
    uint16_t len;
    lw_devaddr_t *devaddr;
    uint32_t fcnt32;
	uint16_t confFCnt;
	uint8_t txDr;
	uint8_t txCh;
}lw_key_mic11_t;

void lw_msg_mic(lw_mic_t* mic, lw_key_t *key);
void lw_msg_mic11(lw_mic_t *mic, lw_key_mic11_t *key);
void lw_join_mic(lw_mic_t* mic, lw_key_t *key);
int lw_encrypt(uint8_t *out, lw_key_t *key);
int lw_join_decrypt(uint8_t *out, lw_key_t *key);
int lw_join_encrypt(uint8_t *out, lw_key_t *key);
void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed);
void lw_get_skeys_11(uint8_t *FNwkSntKey, uint8_t* SNwkSIntKey, uint8_t* NwkSEncKey, uint8_t *AppSKey, lw_skey_seed_11_t *seed);

void encrypt_fopts(uint8_t *data, uint8_t dataLen, uint8_t *key, bool aFCntDown, bool isUplink, lw_devaddr_t *devaddr, uint32_t cnt);

#endif /* DRV_LOBAWAN_LW_CRYPTO_H_ */
