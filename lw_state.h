/**************************************************************************
 Copyright (c) 2017 Theodor Tobias Rohde (tr@lobaro.com)
 Lobaro - Industrial IoT Solutions
 www.lobaro.com

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

#ifndef _LW_STATE_H_
#define _LW_STATE_H_

#include <stdint.h>

typedef enum {
	LORAWAN_VERSION_UNKNOWN = 0x00,
	LORAWAN_VERSION_1_0 = 0x10,
	LORAWAN_VERSION_1_1 = 0x11,
} Lorawan_version_t;

// LoRaWAN device config / state parameter
// todo add LoRaWAN 1.1 functionality
typedef struct {
	// this stores the version actually used (after OTAA negotiation)
	Lorawan_version_t LorawanVersion;

	// 4 Byte address assigned in OTAA Join or by ABP
	uint32_t DevAddr;

	// EUIs (used for OTAA join only)
	// EUI are 8 bytes multi-octet fields and are transmitted as little endian. (LoRaWAN Specification)
	// ->  if the EUI-64 is 70-B3-D5-7E-F0-00-48-9C it would be in the air as 9C-48-00...
	// LoRaWAN_MarshalPacket will take care of this (make the little endian conversion)
	uint8_t JoinEUI[8]; // before LoRaWAN1.1 this was also called the appEUI
	uint8_t DevEUI[8];

	// 128 Bit keys

	// device root keys, used to derive the four session keys during join
	// [spec:1.1:1333]
	uint8_t AppKey[16];  // OTAA only
	uint8_t NwkKey[16];  // OTAA only, since 1.1

	// OTAA lifetime keys (derived from NwkKey) [spec:1.1:1366]
	uint8_t JSIntKey[16];
	uint8_t JSEncKey[16];

	// session keys, set directly for ABP or set during join for OTAA [spec:1.1:1375]
	uint8_t NwkSEncKey[16];
	uint8_t SNwkSIntKey[16];
	uint8_t FNwkSIntKey[16];
	uint8_t AppSKey[16];

	// OTAA only:
	// used for/in join request msg (issued by client/sensor) [spec:1.1:1500]
	uint16_t DevNonce;  // counter starting from 0 and increments for every join request. SHALL NEVER be reused for given JoinEUI
	// [spec:1.1:1550] sent by server, never repeats itself, SHALL be persisted in non-volatile memory.
	uint16_t JoinNonce;  // aka AppNonce in LoRaWAN 1.0

	// network identifier, 24 bits [Spec:1.1:1543]
	uint32_t NetID;
} Lorawan_devCfg_t;

// LoRaWAN network control / state parameter
typedef struct {
	uint32_t FCntUp;

	// NFCntDwn is FCntDown (LW 1.0) for all communications on LoRaWAN 1.0.1
	// NFCntDwn is used for MAC communication on port 0 and when the FPort field is missing (LoRaWAN 1.1 only)
	// In the two counters scheme the NFCntDown is managed by the Network Server, whereas
	// the AFCntDown is managed by the application server
	uint32_t NFCntDwn;
	// AFCntDwn is used for all ports > 0 when the device operates as a LoRaWAN 1.1
	uint32_t AFCntDwn;

} Lorawan_fcnt_t;

#endif
