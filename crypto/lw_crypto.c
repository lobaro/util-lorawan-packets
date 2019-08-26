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

#include <stdint.h>
#include <string.h> // memset
#include <github.com/lobaro/c-utils/lobaroAssert.h>

#include "lw_crypto.h"
#include "cmac.h"

#define LW_KEY_LEN                          (16)
#define LW_MIC_LEN                          (4)

static void lw_write_dw(uint8_t *output, uint32_t input)
{
	uint8_t* ptr = output;

	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr++) = (uint8_t)(input), input >>= 8u;
	*(ptr) = (uint8_t)(input);
}

//static uint32_t lw_read_dw(uint8_t *buf)
//{
//	uint32_t ret;
//
//	ret = ( (uint32_t)buf[0] << 0 );
//    ret |= ( (uint32_t)buf[1] << 8 );
//    ret |= ( (uint32_t)buf[2] << 16 );
//    ret |= ( (uint32_t)buf[3] << 24 );
//
//	return ret;
//}

void lw_msg_mic(lw_mic_t* mic, lw_key_t *key)
{
    uint8_t b0[LW_KEY_LEN];
    memset(b0, 0 , LW_KEY_LEN);
    b0[0] = 0x49;
// todo add LoRaWAN 1.1 support for b0[1..4]
//  LoRaWAN 1.1 spec, 4.4:
//  If the device is connected to a LoRaWAN1.1 Network Server and the ACK bit of the downlink frame is set,
//	meaning this frame is acknowledging an uplink �confirmed� frame,
//	then ConfFCnt is the frame counter value modulo 2^16 of the �confirmed� uplink frame that is being acknowledged.
//	In all other cases ConfFCnt = 0x0000.
    b0[5] = key->link;

    lw_write_dw(b0+6, key->devaddr.data);
    lw_write_dw(b0+10, key->fcnt32);
    b0[15] = (uint8_t)key->len;

	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

void lw_msg_mic11(lw_mic_t *mic, lw_key_mic11_t *key) {
	uint8_t b0[LW_KEY_LEN];
	memset(b0, 0 , LW_KEY_LEN);
	b0[0] = 0x49;
// todo add LoRaWAN 1.1 support for b0[1..4]
//  LoRaWAN 1.1 spec, 4.4:
//  If the device is connected to a LoRaWAN1.1 Network Server and the ACK bit of the downlink frame is set,
//	meaning this frame is acknowledging an uplink �confirmed� frame,
//	then ConfFCnt is the frame counter value modulo 2^16 of the �confirmed� uplink frame that is being acknowledged.
//	In all other cases ConfFCnt = 0x0000.
	b0[1] = key->confFCnt & 0xffu;
	b0[2] = key->confFCnt >> 0x8u;
	b0[3] = key->txDr;
	b0[4] = key->txCh;
	b0[5] = 0x00;  // Dir = 0x00
	lw_write_dw(b0+6, key->devaddr->data);  // 6 - 9
	lw_write_dw(b0+10, key->fcnt32);  // 10-13
	b0[14] = 0x00;
	b0[15] = (uint8_t)key->len;

/*	log("B1: ");
	for (int i=0; i<LW_KEY_LEN; i++) {
		log("%02x", b0[i]);
	}
	log("\n");*/

	// cmacS = aes128_cmac(SNwkSIntKey, B1 | msg)
	AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->snwksintkey);
	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);
	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);
	memcpy(mic->buf, temp, 2);

	// cmacF = aes128_cmac(FNwkSIntKey, B0 | msg)
	b0[1] = b0[2] = b0[3] = b0[4] = 0x00;
/*	log("B0: ");
	for (int i=0; i<LW_KEY_LEN; i++) {
		log("%02x", b0[i]);
	}
	log("\n");*/
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->fnwksintkey);
	AES_CMAC_Update(&cmacctx, b0, LW_KEY_LEN);
	AES_CMAC_Update(&cmacctx, key->in, key->len);
	AES_CMAC_Final(temp, &cmacctx);
	memcpy(mic->buf + 2, temp, 2);
}

void lw_join_mic(lw_mic_t* mic, lw_key_t *key)
{
    AES_CMAC_CTX cmacctx;
	AES_CMAC_Init(&cmacctx);
	AES_CMAC_SetKey(&cmacctx, key->aeskey);

	AES_CMAC_Update(&cmacctx, key->in, key->len);

	uint8_t temp[LW_KEY_LEN];
	AES_CMAC_Final(temp, &cmacctx);

	memcpy(mic->buf, temp, LW_MIC_LEN);
}

// Use to generate JoinAccept Payload
int lw_join_encrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_decrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

// Use to decrypt JoinAccept Payload
int lw_join_decrypt(uint8_t *out, lw_key_t *key)
{
    if((key->len == 0) || (key->len%LW_KEY_LEN != 0)){
        return -1;
    }

    aes_context aesContext;

	aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

    // Check if optional CFList is included
    int i;
    for(i=0; i<key->len; i+=LW_KEY_LEN){
        aes_encrypt( key->in + i, out + i, &aesContext );
    }

    return key->len;
}

static void lw_block_xor(uint8_t const l[], uint8_t const r[], uint8_t out[], uint16_t bytes)
{
	uint8_t const* lptr = l;
	uint8_t const* rptr = r;
	uint8_t* optr = out;
	uint8_t const* const end = out + bytes;

	for (;optr < end; lptr++, rptr++, optr++)
		*optr = *lptr ^ *rptr;
}

int lw_encrypt(uint8_t *out, lw_key_t *key)
{
    if (key->len == 0)
		return -1;

	uint8_t A[LW_KEY_LEN];

	uint16_t const over_hang_bytes = key->len%LW_KEY_LEN;
    int blocks = key->len/LW_KEY_LEN + 1;

	memset(A, 0, LW_KEY_LEN);

	A[0] = 0x01; //encryption flags
	A[5] = key->link;

	lw_write_dw(A+6, key->devaddr.data);
	lw_write_dw(A+10, key->fcnt32);

	uint8_t const* blockInput = key->in;
	uint8_t* blockOutput = out;
	uint16_t i;
	for(i = 1; i <= blocks; i++, blockInput += LW_KEY_LEN, blockOutput += LW_KEY_LEN){
		A[15] = (uint8_t)(i);

		aes_context aesContext;
		aes_set_key(key->aeskey, LW_KEY_LEN, &aesContext);

		uint8_t S[LW_KEY_LEN];
		aes_encrypt(A, S, &aesContext);

		uint16_t bytes_to_encrypt;
		if ((i < blocks) || (over_hang_bytes == 0))
			bytes_to_encrypt = LW_KEY_LEN;
		else
			bytes_to_encrypt = over_hang_bytes;

		lw_block_xor(S, blockInput, blockOutput, bytes_to_encrypt);
	}
	return key->len;
}


void lw_get_skeys(uint8_t *nwkskey, uint8_t *appskey, lw_skey_seed_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
    memset(b, 0, LW_KEY_LEN);
    b[1] = (uint8_t)(seed->anonce.data>>0u);
    b[2] = (uint8_t)(seed->anonce.data>>8u);
    b[3] = (uint8_t)(seed->anonce.data>>16u);
    b[4] = (uint8_t)(seed->netid.data>>0u);
    b[5] = (uint8_t)(seed->netid.data>>8u);
    b[6] = (uint8_t)(seed->netid.data>>16u);
    b[7] = (uint8_t)(seed->dnonce.data>>0u);
    b[8] = (uint8_t)(seed->dnonce.data>>8u);

    b[0] = 0x01;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, nwkskey, &aesContext );

    b[0] = 0x02;
	aes_set_key(seed->aeskey, LW_KEY_LEN, &aesContext);
    aes_encrypt( b, appskey, &aesContext );
}

void lw_get_skeys_11(uint8_t *FNwkSntKey, uint8_t* SNwkSIntKey, uint8_t* NwkSEncKey, uint8_t *AppSKey, lw_skey_seed_11_t *seed)
{
    aes_context aesContext;
    uint8_t b[LW_KEY_LEN];

    memset(&aesContext, 0, sizeof(aesContext));
	memset(b, 0, LW_KEY_LEN);
	b[1] = (uint8_t)(seed->jnonce.data>>0u);
	b[2] = (uint8_t)(seed->jnonce.data>>8u);
	b[3] = (uint8_t)(seed->jnonce.data>>16u);
	b[4] = seed->joineui[7];
	b[5] = seed->joineui[6];
	b[6] = seed->joineui[5];
	b[7] = seed->joineui[4];
	b[8] = seed->joineui[3];
	b[9] = seed->joineui[2];
	b[10] = seed->joineui[1];
	b[11] = seed->joineui[0];
	b[12] = (uint8_t)(seed->dnonce.data>>0u);
	b[13] = (uint8_t)(seed->dnonce.data>>8u);

    b[0] = 0x01;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, FNwkSntKey, &aesContext);

	b[0] = 0x02;
	aes_set_key(seed->appkey, LW_KEY_LEN, &aesContext);
	aes_encrypt(b, AppSKey, &aesContext);

    b[0] = 0x03;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, SNwkSIntKey, &aesContext);

    b[0] = 0x04;
	aes_set_key(seed->nwkkey, LW_KEY_LEN, &aesContext);
    aes_encrypt(b, NwkSEncKey, &aesContext);
}

/**
 * En- or decrypt FOpts. Only used for LoRaWAN >= 1.1
 * @param data
 * @param dataLen
 * @param key
 * @param isUplink
 * @param devaddr
 * @param cnt
 */
void encrypt_fopts(uint8_t *data, uint8_t dataLen, uint8_t *key, bool aFCntDown, bool isUplink, lw_devaddr_t *devaddr,
				   uint32_t cnt) {
	lobaroASSERT(dataLen <= 15);
	uint8_t A[16];
	A[0] = 0x01;
	A[1] = A[2] = A[3] = 0x00;
	A[4] = (aFCntDown ? 0x02 : 0x01);
	A[5] = (isUplink ? 0 : 1);
	lw_write_dw(A + 6, devaddr->data);
	lw_write_dw(A + 10, cnt);
	A[14] = 0x00;
	A[15] = 0x01;

	aes_context aesContext;
	aes_set_key(key, LW_KEY_LEN, &aesContext);
	uint8_t S[16];
	aes_encrypt(A, S, &aesContext);

	for (uint8_t i=0; i<dataLen; i++) {
		data[i] ^= S[i];
	}
}
