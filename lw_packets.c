#line __LINE__ "lw_packets.c"
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h> // for memcpy
#include <stdlib.h> // for NULL

#ifndef lobaroASSERT

#include <assert.h>
#include <inttypes.h>

#define lobaroASSERT(x) assert(x)
#endif

#include "crypto/lw_crypto.h"
#include "lw_packets.h"

typedef struct {
	lwPackets_api_t api;
	lwPackets_state_t state;
	bool initDone;
} lwPacketsLib_t;

static lwPacketsLib_t lib = {.initDone = false}; // holds external dependencies

static uint16_t parseUInt16LittleEndian(uint8_t* bytes) {
	return (((uint16_t) bytes[0]) << 0) | (((uint16_t) bytes[1]) << 8);
}

static uint32_t parseUInt32LittleEndian(uint8_t* bytes) {
	return (((uint32_t) bytes[0]) << 0) | (((uint32_t) bytes[1]) << 8) | (((uint32_t) bytes[2]) << 16) | (((uint32_t) bytes[3]) << 24);
}

// EUI are 8 bytes multi-octet fields and are transmitted as little endian.
static void convertInPlaceEUI64bufLittleEndian(uint8_t* eui8buf) {
	uint8_t tmp[8];
	if (eui8buf) {
		memcpy(tmp, eui8buf, 8);
		for (int i = 0; i < 8; i++) {
			eui8buf[i] = tmp[7 - i];
		}
	}
}

static void logNothingDummy(const char* format, ...) {
	return;
//  example log function may be implemented by app/user (#include <stdarg.h>, #include <stdio.h>) :
//	char buffer[100];
//	va_list args;
//	va_start(args, format);
//	int len = vsnprintf(buffer, sizeof(buffer), format, args);
//	if (len > 100 - 1) {
//			strcpy(&buffer[100 - 5], "...\n");
//	}
//	va_end(args);
//	puts(buffer); // or custom uart puts
}

void LoRaWAN_PacketsUtil_Init(lwPackets_api_t api, lwPackets_state_t state) {
	lib.api = api;
	lib.state = state;

	if (lib.api.LogError == NULL) {
		lib.api.LogError = logNothingDummy;
	}

	if (lib.api.LogInfo == NULL) {
		lib.api.LogInfo = logNothingDummy;
	}

	if (lib.api.free == NULL || lib.api.malloc == NULL) {
		lib.api.LogInfo("LW Packets: using c malloc and free default\n");
		lib.api.free = free; // from <stdlib.h>
		lib.api.malloc = malloc; // from <stdlib.h>
	}

	lib.initDone = true;
}

lorawan_packet_t* LoRaWAN_NewPacket(uint8_t* payload, uint8_t length) {
	lobaroASSERT(lib.initDone);
	lobaroASSERT(length <= 222); // max payload size of lorawan EU868 (see 2.1.6 lorawan 1.1 regional parameters)

	lorawan_packet_t* packet = (lorawan_packet_t*) lib.api.malloc(sizeof(lorawan_packet_t));
	if (packet == NULL) {
		return NULL;
	}
	memset(packet, 0, sizeof(lorawan_packet_t));

	if (payload != NULL && length) {

		uint8_t* dataCpy = (uint8_t*) lib.api.malloc(length);
		if (dataCpy == NULL) {
			lib.api.free(packet);
			return NULL;
		}
		memcpy(dataCpy, payload, length);

		packet->BODY.MACPayload.payloadLength = length;
		packet->pPayload = dataCpy; // just to get sure if user creates a packet with payload but uses it as join packet afterwards (see also DeletePacket fkt)
	}

	// static field
	packet->MHDR.version = LORAWAN_R1;
	return packet;
}

void LoRaWAN_DeletePacket(lorawan_packet_t* packet) {
	lobaroASSERT(lib.initDone);

	if (packet == NULL) {
		return;
	}

	// don't rely on packets MHDR type if there is any payload memory to free
	if (packet->pPayload) {
		lib.api.free(packet->pPayload);
		packet->pPayload = NULL;
	}

	lib.api.free(packet);
}

// Marshal the packet into a given buffer, returns the actual size
// Returns -1 when the buffer is too small

uint8_t LoRaWAN_MarshalPacket(lorawan_packet_t* packet, uint8_t* outBuffer, uint8_t bufferSize) {
	uint8_t pos = 0;
	int optLen = 0;
	lw_mic_t mic;     // 4 byte lorawan message integrity code (last bytes of PHYPayload)
	lw_key_t lw_key; // lorawan aes de/encrypt input struct (see crypto.c for details)

	lobaroASSERT(lib.initDone);

	if (bufferSize < 4) {
		return pos;
	}

	// MHDR
	outBuffer[pos++] = (packet->MHDR.type << 5) | (packet->MHDR.version);

	if (packet->MHDR.type == MTYPE_UNCONFIRMED_DATA_UP
		|| packet->MHDR.type == MTYPE_CONFIRMED_DATA_UP) {
		lw_key.link = LW_UPLINK;
		// marshaling continues below if

	} else if (packet->MHDR.type == MTYPE_UNCONFIRMED_DATA_DOWN
			   || packet->MHDR.type == MTYPE_CONFIRMED_DATA_DOWN) {
		lw_key.link = LW_DOWNLINK;
		// marshaling continues below if

	} else if (packet->MHDR.type == MTYPE_JOIN_REQUEST) {
		// EUI are 8 bytes multi-octet fields and are transmitted as little endian. (LoRaWAN Specification)
		// ->  if the EUI-64 is 70-B3-D5-7E-F0-00-48-9C it would be in the air as 9C-48-00...
		// convertInPlaceEUI64bufLittleEndian performs this byte order inversion in place

		if (bufferSize < pos + 8) {
			return 0;
		}
		memcpy(outBuffer + pos, lib.state.pDevCfg->joinEUI, 8);
		convertInPlaceEUI64bufLittleEndian(outBuffer + pos);
		pos += 8;

		if (bufferSize < pos + 8) {
			return 0;
		}
		memcpy(outBuffer + pos, lib.state.pDevCfg->devEUI, 8);
		convertInPlaceEUI64bufLittleEndian(outBuffer + pos);
		pos += 8;

		if (bufferSize < pos + 2) {
			return 0;
		}
		outBuffer[pos++] = (uint8_t) (lib.state.pDevCfg->devnonce & 0xff);
		outBuffer[pos++] = (uint8_t) (lib.state.pDevCfg->devnonce >> 8);

		lw_key.aeskey = lib.state.pDevCfg->appkey;
		lw_key.in = outBuffer;
		lw_key.len = pos;
		lw_join_mic(&mic, &lw_key);

		if (bufferSize < pos + 4) {
			return 0;
		}
		memcpy(outBuffer + pos, mic.buf, 4);
		packet->MIC = mic.data;
		pos += 4;
		return pos;
	} else if (packet->MHDR.type == MTYPE_JOIN_ACCEPT) {
		// normally not needed by a lorawan device but included for completeness (issued by a network server only!)
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.JoinNonce >> 0);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.JoinNonce >> 8);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.JoinNonce >> 16);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.HomeNetID >> 0);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.HomeNetID >> 8);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.HomeNetID >> 16);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.DevAddr >> 0);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.DevAddr >> 8);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.DevAddr >> 16);
		outBuffer[pos++] = (uint8_t) (packet->BODY.JoinAccept.DevAddr >> 24);

		uint8_t dlsettings = 0;
		dlsettings |= ((uint8_t) packet->BODY.JoinAccept.DLsettings.Rx1DRoffset) << 4;
		dlsettings |= ((uint8_t) packet->BODY.JoinAccept.DLsettings.Rx2DR);
		outBuffer[pos++] = dlsettings;

		outBuffer[pos++] = packet->BODY.JoinAccept.RxDelay;
		if (packet->BODY.JoinAccept.hasCFlist) {
			memcpy(&(outBuffer[pos]), packet->BODY.JoinAccept.CFlist.FreqCH4, 3);
			pos += 3;
			memcpy(&(outBuffer[pos]), packet->BODY.JoinAccept.CFlist.FreqCH5, 3);
			pos += 3;
			memcpy(&(outBuffer[pos]), packet->BODY.JoinAccept.CFlist.FreqCH6, 3);
			pos += 3;
			memcpy(&(outBuffer[pos]), packet->BODY.JoinAccept.CFlist.FreqCH7, 3);
			pos += 3;
			memcpy(&(outBuffer[pos]), packet->BODY.JoinAccept.CFlist.FreqCH8, 3);
			pos += 3;
		}

		// calc mic
		lw_key.aeskey = lib.state.pDevCfg->appkey;
		lw_key.in = outBuffer;
		lw_key.len = pos;
		lw_join_mic(&mic, &lw_key);
		memcpy(outBuffer + pos, mic.buf, 4);
		pos += 4;

		// encryp msg
		uint8_t out[33];
		lw_key.aeskey = lib.state.pDevCfg->appkey;
		lw_key.in = outBuffer + 1; // skip MHDR byte
		lw_key.len = pos - 1;
		lw_join_encrypt(out, &lw_key);
		memcpy(outBuffer + 1, out, lw_key.len);
		return pos;

	} else {
		return 0;
		lib.api.LogError("unknown LoRaWAN msg type for marshaling!");
	}

	// FHDR
	if (bufferSize < pos + 4) {
		return 0;
	}
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr & 0xff);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 8);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 16);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 24);
	lw_key.devaddr.data = packet->BODY.MACPayload.FHDR.DevAddr;

	if (lw_key.link == LW_UPLINK) {
		// uplink packet
		if (bufferSize < pos + 1) {
			return 0;
		}
		outBuffer[pos++] = (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADR << 7)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADRACKReq << 6)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ACK << 5)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen);

		optLen = packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen;

	} else if (packet->MHDR.type == MTYPE_UNCONFIRMED_DATA_DOWN
			   || packet->MHDR.type == MTYPE_CONFIRMED_DATA_DOWN) {

		// downlink packet
		if (bufferSize < pos + 1) {
			return 0;
		}
		outBuffer[pos++] = (packet->BODY.MACPayload.FHDR.FCtrl.downlink.ADR << 7)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.downlink.RFU << 6)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.downlink.ACK << 5)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.downlink.FPending << 4)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen);

		optLen = packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen;

	} else {
		lobaroASSERT("join accept, request not implemented yet! (we aren't a network server yet!)");
	}

	// Little endian
	if (bufferSize < pos + 2) {
		return 0;
	}
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.FCnt16 & 0xff);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.FCnt16 >> 8);
	lw_key.fcnt32 = packet->BODY.MACPayload.FHDR.FCnt16;

	if (optLen) {
		if (bufferSize < pos + optLen) {
			return 0;
		}
		memcpy(outBuffer + pos, packet->BODY.MACPayload.FHDR.FOpts, optLen);
		pos += optLen;
	}

	// encrypt payload (if present)
	if (packet->BODY.MACPayload.payloadLength != 0) {
		if (bufferSize < pos + 1) {
			return 0;
		}
		outBuffer[pos++] = packet->BODY.MACPayload.FPort;
		if (packet->BODY.MACPayload.FPort == 0) {
			lw_key.aeskey = lib.state.pDevCfg->nwkskey; // todo maybe add this as parameter?
		} else {
			lw_key.aeskey = lib.state.pDevCfg->appskey;
		}

		lw_key.in = packet->pPayload;
		lw_key.len = packet->BODY.MACPayload.payloadLength;

		int cryptedPayloadLength = lw_encrypt(outBuffer + pos, &lw_key);
		pos += cryptedPayloadLength;
		if (bufferSize < pos) { // TODO: This is too late, we should predict or limit the buffer inside lw_encrypt
			lobaroASSERT(false);
			return 0;
		}
	}

	// 4 byte MIC
	if (bufferSize < pos + 4) {
		return 0;
	}
	lw_key.aeskey = lib.state.pDevCfg->nwkskey;
	lw_key.in = outBuffer;
	lw_key.len = pos;

	lw_msg_mic(&mic, &lw_key);
	memcpy(outBuffer + pos, mic.buf, 4);
	pos += 4;

	return pos;
}

// Like LoRaWAN_NewPacket but takes a marshaled packet as input
// MUST be freed with LoRaWAN_DeletePacket
// data is the raw packet as produced by LoRaWAN_MarshalPacket
lorawan_packet_t* LoRaWAN_UnmarshalPacket(uint8_t* dataToParse, uint8_t length) { // todo add keys as parameter
	uint8_t idx;
	lw_mic_t micCalc;        // calculated mic
	lw_key_t lw_key;

	lobaroASSERT(lib.initDone);
	if (length < 3) {
		return NULL;
	}

	lorawan_packet_t* packet = (lorawan_packet_t*) lib.api.malloc(sizeof(lorawan_packet_t));
	if (packet == NULL) {
		lib.api.LogError("Lobawan: Out of memory\n");
		return NULL;
	}
	memset(packet, 0, sizeof(lorawan_packet_t));

	// MHDR
	idx = 0;
	packet->MHDR.type = dataToParse[idx] >> 5;
	packet->MHDR.version = dataToParse[idx] & 0x3;
	idx++;

	if (packet->MHDR.type == MTYPE_PROPRIETARY) {
		lib.api.LogError("Lobawan: Got proprietary MHDR -> discard msg\n");
		lib.api.free(packet);
		return NULL;
	}

	switch (packet->MHDR.type) {

		case MTYPE_UNCONFIRMED_DATA_UP:
		case MTYPE_CONFIRMED_DATA_UP:
		case MTYPE_UNCONFIRMED_DATA_DOWN:
		case MTYPE_CONFIRMED_DATA_DOWN:
			idx = 1; // skip already parsed MHDR

			// get devAdr since we need it for MIC check
			packet->BODY.MACPayload.FHDR.DevAddr = parseUInt32LittleEndian(&(dataToParse[idx]));
			idx += 4;
			uint8_t fctrl = dataToParse[idx];
			idx++;
			packet->BODY.MACPayload.FHDR.FCnt16 = parseUInt16LittleEndian(&(dataToParse[idx]));
			idx += 2;

			lw_key.aeskey = lib.state.pDevCfg->nwkskey;
			lw_key.in = dataToParse;
			lw_key.len = length - 4;
			lw_key.devaddr.data = packet->BODY.MACPayload.FHDR.DevAddr;

			uint32_t currFcnt32;
			bool uplink = false;
			if (packet->MHDR.type == MTYPE_UNCONFIRMED_DATA_UP || packet->MHDR.type == MTYPE_UNCONFIRMED_DATA_UP) {
				uplink = true;
				lw_key.link = LW_UPLINK;
				currFcnt32 = lib.state.pFCntCtrl->FCntUp;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADR = fctrl >> 7;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADRACKReq = (fctrl & (1 << 6)) >> 6;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ACK = (fctrl & (1 << 5)) >> 5;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ClassB = (fctrl & (1 << 4)) >> 4;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen = (fctrl & 0x0f);

			} else { // downlink
				lw_key.link = LW_DOWNLINK;
				currFcnt32 = lib.state.pFCntCtrl->AFCntDown;
#if USE_LORAWAN_1_1 == 1
#error "missing implementation for NFCntDown"
#endif
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADR = fctrl >> 7;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.ACK = (fctrl & (1 << 5)) >> 5;
				packet->BODY.MACPayload.FHDR.FCtrl.downlink.FPending = (fctrl & (1 << 4)) >> 4;
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen = (fctrl & 0x0f);
			}

			uint16_t currFcnt32_LSB = (uint16_t) currFcnt32;
			uint16_t currFcnt32_MSB = (uint16_t) (currFcnt32 >> 16);
			if (packet->BODY.MACPayload.FHDR.FCnt16 < currFcnt32_LSB) {
				currFcnt32_MSB++;
			}
			lw_key.fcnt32 = (((uint32_t) currFcnt32_MSB) << 16) + packet->BODY.MACPayload.FHDR.FCnt16;

			// calc & compare mic
			packet->MIC = parseUInt32LittleEndian(dataToParse + length - 4);
			lw_msg_mic(&micCalc, &lw_key);

			if (micCalc.data != packet->MIC) {    // check if mic is ok
				lib.api.LogError("Data %s MIC error! -> discarding incoming packet\n", uplink ? "uplink" : "downlink");
				lib.api.free(packet);
				return NULL;
			}

			memcpy(packet->BODY.MACPayload.FHDR.FOpts, &(dataToParse[idx]), packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen);
			idx += packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen;

			// copy other fields & decrypt payload (if present)
			uint8_t lengthWithoutPayloadAndPort = (1 + 7 + packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen + 4);  // MHDR(1) + FHDR(7) + FHDR_OPTS(x) + MIC (4)

			if (length > lengthWithoutPayloadAndPort) {
				packet->BODY.MACPayload.FPort = dataToParse[idx++];
				if (length == lengthWithoutPayloadAndPort + 1) { // no payload, but port
					packet->BODY.MACPayload.payloadLength = 0;
					lib.api.LogError("Lobawan: warn packet with port but without payload\n");
				} else {
					packet->BODY.MACPayload.payloadLength = length - 4 - idx;

					if (packet->BODY.MACPayload.FPort == 0) {
						lw_key.aeskey = lib.state.pDevCfg->nwkskey;
					} else {
						lw_key.aeskey = lib.state.pDevCfg->appskey;
					}
					lw_key.in = &(dataToParse[idx]);
					lw_key.len = packet->BODY.MACPayload.payloadLength;

					packet->pPayload = (uint8_t*) lib.api.malloc(packet->BODY.MACPayload.payloadLength);

					if (packet->pPayload == NULL) {
						lib.api.LogError("LoRaWAN_UnmarshalPacket failed -> out of memory!\n");
						lib.api.free(packet);
						return NULL;
					}

					// decrypt by encrypt
					if (lw_encrypt(packet->pPayload, &lw_key) <= 0) {
						lib.api.LogError("LoRaWAN_UnmarshalPacket decrypt fail\n");
						lib.api.free(packet->pPayload);
						lib.api.free(packet);
						return NULL;
					}
				}

			} else { // no payload, no port, no cry
				packet->BODY.MACPayload.payloadLength = 0;
				packet->pPayload = NULL;
			}

			return packet;

		case MTYPE_JOIN_ACCEPT:

			// MHDR(1) + [sizeof(JoinAccept_t)(12) + optional CFlist(16)] + MIC(4), max len: 33 byte
			if (length == 17) {
				packet->BODY.JoinAccept.hasCFlist = false;
			} else if (length == 17 + 16) {
				packet->BODY.JoinAccept.hasCFlist = true; // optional frequency list send by network server
			} else {
				lib.api.LogError("Lobawan: Got JoinRequest with unexspected length -> discarding incoming packet\n");
				lib.api.free(packet);
				return NULL;
			}

			// (1) beside MHDR whole the message is encrypted -> decrypt it first
			uint8_t decryptedData[33]; // temp buffer
			lw_key.aeskey = lib.state.pDevCfg->appkey;
			lw_key.in = dataToParse + 1;  // skip MHDR
			lw_key.len = length - 1;
			decryptedData[0] = dataToParse[0]; // MHDR can be copied as it's not encrypted
			int pl_len = lw_join_decrypt(decryptedData + 1, &lw_key);

			if (pl_len <= 0) {
				lib.api.LogError("Lobawan: Can't decrypt JoinRequest\n");
				lib.api.free(packet);
				return NULL;
			}

			// (2) check MIC
			packet->MIC = parseUInt32LittleEndian(decryptedData + length - 4);
			lw_key.aeskey = lib.state.pDevCfg->appkey;
			lw_key.in = decryptedData;
			lw_key.len = length - 4; // skip MIC
			lw_join_mic(&micCalc, &lw_key);
			if (micCalc.data != packet->MIC) {    // check if mic is ok
				lib.api.LogError("Join accept mic error -> discarding incoming packet\n");
				lib.api.free(packet);
				return NULL;
			}

			// (3) parse fields
			idx = 1; // skip already parsed MHDR
			packet->BODY.JoinAccept.JoinNonce = decryptedData[idx++];
			packet->BODY.JoinAccept.JoinNonce |= ((uint32_t) decryptedData[idx++] << 8);
			packet->BODY.JoinAccept.JoinNonce |= ((uint32_t) decryptedData[idx++] << 16);

			packet->BODY.JoinAccept.HomeNetID = decryptedData[idx++];
			packet->BODY.JoinAccept.HomeNetID |= ((uint32_t) decryptedData[idx++] << 8);
			packet->BODY.JoinAccept.HomeNetID |= ((uint32_t) decryptedData[idx++] << 16);

			packet->BODY.JoinAccept.DevAddr = parseUInt32LittleEndian(&(decryptedData[idx]));
			idx += 4;
			packet->BODY.JoinAccept.DLsettings.OptNeg = ((decryptedData[idx] & 0x80) >> 7);
			packet->BODY.JoinAccept.DLsettings.Rx1DRoffset = ((decryptedData[idx] & 0x70) >> 4);
			packet->BODY.JoinAccept.DLsettings.Rx2DR = (decryptedData[idx] & 0x0f);
			idx++;

			packet->BODY.JoinAccept.RxDelay = decryptedData[idx++];

			if (packet->BODY.JoinAccept.hasCFlist) {
				memcpy(packet->BODY.JoinAccept.CFlist.FreqCH4, decryptedData + idx, 3);
				memcpy(packet->BODY.JoinAccept.CFlist.FreqCH5, decryptedData + idx + 3, 3);
				memcpy(packet->BODY.JoinAccept.CFlist.FreqCH6, decryptedData + idx + 6, 3);
				memcpy(packet->BODY.JoinAccept.CFlist.FreqCH7, decryptedData + idx + 9, 3);
				memcpy(packet->BODY.JoinAccept.CFlist.FreqCH8, decryptedData + idx + 12, 3);
			}

			// (4) derive keys
			lw_skey_seed_t lw_skey_seed;
			lw_skey_seed.aeskey = lib.state.pDevCfg->appkey;
			lw_skey_seed.anonce.data = packet->BODY.JoinAccept.JoinNonce;
			lw_skey_seed.netid.data = packet->BODY.JoinAccept.HomeNetID;
			lw_skey_seed.dnonce.data = lib.state.pDevCfg->devnonce;
			lw_get_skeys(packet->BODY.JoinAccept.derived_nwkskey, packet->BODY.JoinAccept.derived_appskey, &lw_skey_seed); // todo maybe add as special "payload" to packet?

			// app should adjust nwkskey, appskey, devAdr, netId, appnounce
			return packet;

		case MTYPE_JOIN_REQUEST:
			// normally NOT needed to parse by a lorawan device but included for completeness (Unmarshalled by network servers only!)
			if (length != 23) { // MHDR(1) + [APPEUI(8) + DEVEUI(8) + DEVNOUNCE(2)] + MIC(4)
				lib.api.LogError("Lobawan: Got JoinRequest with unexspected length -> discarding incoming packet\n");
				lib.api.free(packet);
				return NULL;
			}

			packet->MIC = parseUInt32LittleEndian(dataToParse + length - 4);

			lw_key.aeskey = lib.state.pDevCfg->appkey;
			lw_key.in = dataToParse;
			lw_key.len = length - 4;
			lw_join_mic(&micCalc, &lw_key);

			// check if mic is ok
			if (micCalc.data != packet->MIC) {
				lib.api.LogError("Join Request mic error -> discarding incoming packet\n");
				lib.api.free(packet);
				return NULL;
			}

			idx = 1; // skip already parsed MHDR
			memcpy(packet->BODY.JoinRequest.joinEUI, dataToParse + idx, 8);
			idx += 8;
			memcpy(packet->BODY.JoinRequest.devEUI, dataToParse + idx, 8);
			idx += 8;

			packet->BODY.JoinRequest.devnonce = parseUInt16LittleEndian(&(dataToParse[idx]));
			//idx += 2;
			return packet;

		default:
			lib.api.LogError("Lobawan: unknown MHDR type -> discarding incoming packet\n");
			lib.api.free(packet);
			return NULL;
	}

	return packet;
}

