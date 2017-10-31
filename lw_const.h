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

#ifndef _LW_CONST_H_
#define _LW_CONST_H_

// LoRaWAN device config / state parameter
// todo add LoRaWAN 1.1 functionality
typedef struct {
	uint32_t DevAddr;

	// 128 Bit keys
	uint8_t nwkskey[16];
	uint8_t appskey[16];
	uint8_t appkey[16]; // OTAA only

	// EUIs (used for OTAA join only)
	uint8_t joinEUI[8]; // before LoRaWAN1.1 this was also called the appEUI
	uint8_t devEUI[8];

	// OTAA only:
	// used for/in join request msg (issued by client/sensor)
	uint16_t devnonce; // must be random for each join request

	// used for/in join accept msg (issued by network server)
	uint32_t appnonce; // aka joinnonce in lorawan 1.1, If the device is susceptible of being power cycled the JoinNonce SHALL be persistent
	uint32_t netid;
} Lorawan_devCfg_t;

// LoRaWAN network control / state parameter
typedef struct {
	uint32_t FCntUp;
	uint32_t AFCntDown;				// used for all other ports when the device operates as a LoRaWAN 1.1 or for all communications on LoRaWAN 1.0.1

	// new in LoRaWAN 1.1 (not supported yet!)
	uint32_t NFCntDown;				// used for MAC communication on port 0 and when the FPort field is missing (LoRaWAN 1.1 only)
									// In the two counters scheme the NFCntDown is managed by the Network Server, whereas
									// the AFCntDown is managed by the application server
} Lorawan_netCtrl_t;

#endif
