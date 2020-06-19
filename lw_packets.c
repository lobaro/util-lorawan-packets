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

#if configUSE_FREERTOS == 1

#include "FreeRTOSConfig.h"

#define lobaroASSERT(x) configASSERT(x)
#else
#define lobaroASSERT(x) assert(x)
#endif
#endif

#include "crypto/lw_crypto.h"
#include "lw_packets.h"

#include "module_logging.h"

#if configLOG_LOBAWAN == 1
#define LOG(...) lib.api.LogInfo(__VA_ARGS__)
#else
#define LOG(...) {}
#endif

typedef struct {
	lwPackets_api_t api;
	lwPackets_state_t state;
	bool initDone;
} lwPacketsLib_t;

static lwPacketsLib_t lib = {.initDone = false}; // holds external dependencies

static uint16_t parseUInt16LittleEndian(const uint8_t *bytes) {
	return (((uint16_t) bytes[0]) << 0u) | (((uint16_t) bytes[1]) << 8u);
}

static uint32_t parseUInt32LittleEndian(const uint8_t *bytes) {
	return (((uint32_t) bytes[0]) << 0u) | (((uint32_t) bytes[1]) << 8u) | (((uint32_t) bytes[2]) << 16u) | (((uint32_t) bytes[3]) << 24u);
}

// EUI are 8 bytes multi-octet fields and are transmitted as little endian.
static void convertInPlaceEUI64bufLittleEndian(uint8_t *eui8buf) {
	uint8_t tmp[8];
	if (eui8buf) {
		memcpy(tmp, eui8buf, 8);
		for (int i = 0; i < 8; i++) {
			eui8buf[i] = tmp[7 - i];
		}
	}
}

static void logNothingDummy(const char *format, ...) {
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
		LOG_INFO("LW Packets: using c malloc and free default\n");
		lib.api.free = free; // from <stdlib.h>
		lib.api.malloc = malloc; // from <stdlib.h>
	}

	lib.initDone = true;
}


static const char *mhdrString(MHDR_Mtype_t t) {
	switch (t) {
		case MTYPE_JOIN_REQUEST:
			return "JOIN_REQUEST";
		case MTYPE_JOIN_ACCEPT:
			return "JOIN_ACCEPT";
		case MTYPE_UNCONFIRMED_DATA_UP:
			return "UNCONFIRMED_DATA_UP";
		case MTYPE_UNCONFIRMED_DATA_DOWN:
			return "UNCONFIRMED_DATA_DOWN";
		case MTYPE_CONFIRMED_DATA_UP:
			return "CONFIRMED_DATA_UP";
		case MTYPE_CONFIRMED_DATA_DOWN:
			return "CONFIRMED_DATA_DOWN";
		case MTYPE_REJOIN_REQUEST:
			return "REJOIN_REQUEST";
		case MTYPE_PROPRIETARY:
			return "PROPRIETARY";
		default:
			return "UNKNOWN";
	}
}

// note that MIC can only be printed correctly after marshal was called on the packet
void lorawan_logLoraPacket(lorawan_packet_t *p, bool uplink) {
	LOG("\nLoRa| LoRaWAN Packet (%s)\n", uplink ? "Uplink" : "Downlink");
	LOG("LoRa| --------------\n");
	LOG("LoRa| MIC: %08X\n", p->MIC); // LCTT prints the MIC in inverted byte order ...
	LOG("LoRa| MHDR: %s v%d\n", mhdrString(p->MHDR.type), p->MHDR.version);
	// TODO: We only support MACPayload
	LOG("LoRa| BODY:\n");
	LOG("LoRa| - mac.port: %d\n", p->BODY.MACPayload.FPort);
	LOG("LoRa| - mac.payloadLength: %d\n", p->BODY.MACPayload.payloadLength);
	LOG("LoRa| - mac.FCnt16: %d\n", p->BODY.MACPayload.FHDR.FCnt16);
	LOG("LoRa| - mac.DevAddr: %08x\n", p->BODY.MACPayload.FHDR.DevAddr);

	if (uplink) {
		// Uplink
		LOG("LoRa| - FCtrl: ADR %d, ADRACKReq %d, ACK %d, ClassB %d, FOptsLen %d\n",
			p->BODY.MACPayload.FHDR.FCtrl.uplink.ADR,
			p->BODY.MACPayload.FHDR.FCtrl.uplink.ADRACKReq,
			p->BODY.MACPayload.FHDR.FCtrl.uplink.ACK,
			p->BODY.MACPayload.FHDR.FCtrl.uplink.ClassB,
			p->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen
		);
		if (p->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen > 0) {
			LOG("LoRa| - FOpts: ");
			for (int i = 0; i < p->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen; i++) {
				LOG("%02x", p->BODY.MACPayload.FHDR.FOpts[i]);
			}
			LOG("\n");
		}
	} else {
		// Downlink
		LOG("LoRa| - FCtrl: ADR %d, RFU: %d, ACK %d, FPending %d, FOptsLen %d\n",
			p->BODY.MACPayload.FHDR.FCtrl.downlink.ADR,
			p->BODY.MACPayload.FHDR.FCtrl.downlink.RFU,
			p->BODY.MACPayload.FHDR.FCtrl.downlink.ACK,
			p->BODY.MACPayload.FHDR.FCtrl.downlink.FPending,
			p->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen
		);
		if (p->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen > 0) {
			LOG("LoRa| - FOpts: ");
			for (int i = 0; i < p->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen; i++) {
				LOG("%02x", p->BODY.MACPayload.FHDR.FOpts[i]);
			}
			LOG("\n");
		}
	}
	// Log out payload as hex
	LOG("LoRa| PAYLOAD:");
	if (p->BODY.MACPayload.payloadLength == 0) {
		LOG(" [none]");
	} else {
		for (uint16_t i = 0; i < p->BODY.MACPayload.payloadLength; i++) {
			LOG(" %02x", p->pPayload[i]);
		}
	}
	LOG("\n");
}


lorawan_packet_t *LoRaWAN_NewPacket(const uint8_t *payload, uint8_t length) {
	lobaroASSERT(lib.initDone);
	lobaroASSERT(length <= 222); // max payload size of lorawan EU868 (see 2.1.6 lorawan 1.1 regional parameters)

	lorawan_packet_t *packet = (lorawan_packet_t *) lib.api.malloc(sizeof(lorawan_packet_t));
	if (packet == NULL) {
		return NULL;
	}
	memset(packet, 0, sizeof(lorawan_packet_t));

	if (payload != NULL && length > 0) {
		uint8_t *dataCpy = (uint8_t *) lib.api.malloc(length);
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

void LoRaWAN_DeletePayload(lorawan_packet_t *packet) {
	lobaroASSERT(lib.initDone);

	// don't rely on packets MHDR type if there is any payload memory to free
	if (packet != NULL && packet->pPayload != NULL) {
		lib.api.free(packet->pPayload);
		packet->pPayload = NULL;
		packet->BODY.MACPayload.payloadLength = 0;
	}
}

void LoRaWAN_DeletePacket(lorawan_packet_t *packet) {
	lobaroASSERT(lib.initDone);

	if (packet == NULL) {
		return;
	}

	LoRaWAN_DeletePayload(packet);
	lib.api.free(packet);
}

// Marshal the packet into a given buffer, returns the actual size
// Returns -1 when the buffer is too small

uint8_t LoRaWAN_MarshalPacket(lorawan_packet_t *packet, uint8_t *outBuffer, uint8_t bufferSize) {
	uint8_t pos = 0;
	int optLen = 0;
	lw_mic_t mic;     // 4 byte lorawan message integrity code (last bytes of PHYPayload)
	lw_key_t lw_key; // lorawan aes de/encrypt input struct (see crypto.c for details)

	lobaroASSERT(lib.initDone);

	if (bufferSize < 4) {
		return pos;
	}

	// MHDR
	outBuffer[pos++] = (packet->MHDR.type << 5u) | (packet->MHDR.version);

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
		memcpy(outBuffer + pos, lib.state.pDevCfg->JoinEUI, 8);
		convertInPlaceEUI64bufLittleEndian(outBuffer + pos);
		pos += 8;

		if (bufferSize < pos + 8) {
			return 0;
		}
		memcpy(outBuffer + pos, lib.state.pDevCfg->DevEUI, 8);
		convertInPlaceEUI64bufLittleEndian(outBuffer + pos);
		pos += 8;

		if (bufferSize < pos + 2) {
			return 0;
		}
		outBuffer[pos++] = (uint8_t) (lib.state.pDevCfg->DevNonce & 0xffu);
		outBuffer[pos++] = (uint8_t) (lib.state.pDevCfg->DevNonce >> 8u);

		lw_key.aeskey = lib.state.pDevCfg->NwkKey;
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

	} else {
		LOG_ERROR("LoRa| unknown msg type for marshaling!");
		return 0;
	}

	// FHDR
	if (bufferSize < pos + 4) {
		return 0;
	}
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr & 0xffu);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 8u);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 16u);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.DevAddr >> 24u);
	lw_key.devaddr.data = packet->BODY.MACPayload.FHDR.DevAddr;

	if (lw_key.link == LW_UPLINK) {
		// uplink packet
		if (bufferSize < pos + 1) {
			return 0;
		}
		outBuffer[pos++] = (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADR << 7u)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ADRACKReq << 6u)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.ACK << 5u)
						   | (packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen);

		optLen = packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen;
	} else {
		lobaroASSERT(false); // "join accept, request not implemented yet! (we aren't a network server yet!)");
	}

	// Little endian
	if (bufferSize < pos + 2) {
		return 0;
	}
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.FCnt16 & 0xffu);
	outBuffer[pos++] = (uint8_t) (packet->BODY.MACPayload.FHDR.FCnt16 >> 8u);
	//lw_key.fcnt32 = packet->BODY.MACPayload.FHDR.FCnt16;
	lobaroASSERT((lib.state.pFCntCtrl->FCntUp & 0xffffu) == packet->BODY.MACPayload.FHDR.FCnt16);
	lw_key.fcnt32 = lib.state.pFCntCtrl->FCntUp;

	if (lib.state.pDevCfg->LorawanVersion >= LORAWAN_VERSION_1_1) {
//		LOG_INFO("v1.1, enc FOpts\n");
		// FOpts are only encrypted starting v1.1 (spec fails to state no encryption for 1.0)
		// see https://lora-alliance.org/sites/default/files/2019-08/00001.002.00001.001.cr-fcntdwn-usage-in-fopts-encryption-v2-r1.pdf
		encrypt_fopts(
				packet->BODY.MACPayload.FHDR.FOpts,
				packet->BODY.MACPayload.FHDR.FCtrl.uplink.FOptsLen,
				lib.state.pDevCfg->NwkSEncKey,
				false,
				true,
				&lw_key.devaddr,
				lw_key.fcnt32
		);
	} else {
//		LOG_INFO("v1.0, DON'T FOpts\n");
	}

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
			lw_key.aeskey = lib.state.pDevCfg->NwkSEncKey; // todo maybe add this as parameter?
		} else {
			lw_key.aeskey = lib.state.pDevCfg->AppSKey;
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

	// note that this code is not run for OTAA Join Requests (see return above!)
	if (lib.state.pDevCfg->LorawanVersion == LORAWAN_VERSION_1_0) {
		// v1.0 has MIC calculated with the only used key [spec:1.1:800]
		lw_key.aeskey = lib.state.pDevCfg->FNwkSIntKey;
		lw_key.in = outBuffer;
		lw_key.len = pos;
		lw_msg_mic(&mic, &lw_key);
		memcpy(outBuffer + pos, mic.buf, 4);
		pos += 4;
	} else if (lib.state.pDevCfg->LorawanVersion == LORAWAN_VERSION_1_1) {
		// v1.1 uses forwarding and serving network key for MIC and uses a combination of both [spec:1.1:803]
		lw_key_mic11_t lw_key11;
		lw_key11.fnwksintkey = lib.state.pDevCfg->FNwkSIntKey;
		lw_key11.snwksintkey = lib.state.pDevCfg->SNwkSIntKey;
		lw_key11.devaddr = &lw_key.devaddr;  // just copy from other lw_key version
		lw_key11.fcnt32 = lw_key.fcnt32;
		lw_key11.confFCnt = packet->UplinkMeta.confFCnt;
		lw_key11.txDr = packet->UplinkMeta.txDr;
		lw_key11.txCh = packet->UplinkMeta.txCh;
		lw_key11.in = outBuffer;
		lw_key11.len = pos;
		lw_msg_mic11(&mic, &lw_key11);
		memcpy(outBuffer + pos, mic.buf, 4);
		pos += 4;
	} else {
		lobaroASSERT(false);
	}
	return pos;
}

// Like LoRaWAN_NewPacket but takes a marshaled packet as input
// MUST be freed with LoRaWAN_DeletePacket
// data is the raw packet as produced by LoRaWAN_MarshalPacket
lorawan_packet_t *LoRaWAN_UnmarshalPacketFor(const uint8_t *dataToParse, uint8_t length, uint32_t address) { // todo add keys as parameter
	uint8_t idx;
	lw_mic_t micCalc;        // calculated mic
	lw_key_t lw_key;

	lobaroASSERT(lib.initDone);
	if (length < 3) {
		return NULL;
	}

	lorawan_packet_t *packet = LoRaWAN_NewPacket(NULL, 0);
	if (packet == NULL) {
		LOG_ERROR("LoRa| OOM\n");
		return NULL;
	}

	// MHDR
	idx = 0;
	packet->MHDR.type = dataToParse[idx] >> 5u;
	packet->MHDR.version = dataToParse[idx] & 0x3u;
	idx++;

	if (packet->MHDR.type == MTYPE_PROPRIETARY) {
		LOG_ERROR("LoRa| Got proprietary MHDR -> drop packet\n");
		LoRaWAN_DeletePacket(packet);
		return NULL;
	}

	if (address != 0) {
		// receive for specific address can never be a join accept
		if (packet->MHDR.type == MTYPE_JOIN_ACCEPT) {
			LOG_INFO("LoRa| join accept -> drop packet\n");
			LoRaWAN_DeletePacket(packet);
			return NULL;
		}

	}

	switch (packet->MHDR.type) {
		case MTYPE_UNCONFIRMED_DATA_DOWN:
		case MTYPE_CONFIRMED_DATA_DOWN:
			idx = 1; // skip already parsed MHDR

			// get devAdr since we need it for MIC check
			packet->BODY.MACPayload.FHDR.DevAddr = parseUInt32LittleEndian(&(dataToParse[idx]));
			idx += 4;
			// if we got an address (<>0), we only try to unmarshal messages for that address
			if (address != 0) {
				if (packet->BODY.MACPayload.FHDR.DevAddr == address) {
					LOG_ERROR("LoRa| Received msg for addr %08x, that's me\n", address);
				} else {
					// that message is not for us, ignore it
					LOG_ERROR("LoRa| Received msg for addr %08x (I am %08x), ignoring\n", packet->BODY.MACPayload.FHDR.DevAddr, address);
					LoRaWAN_DeletePacket(packet);
					return NULL;
				}
			}

			// Port is needed to pick correct counter and key, so we do this first:
			packet->BODY.MACPayload.FPort = 0;
			const uint8_t FCTRLPOS = 5;

			if (length > FCTRLPOS) {
				uint8_t foptslen = dataToParse[FCTRLPOS] & 0xfu;
				uint8_t portPos = 1 + 4 + 1 + 2 + foptslen;  // MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2) + FOpts(foptslen)
				if (length - 4 > portPos) {  // -4 Bytes for trailing MIC
					packet->BODY.MACPayload.FPort = dataToParse[portPos];
				}
			}
			// LOG_INFO("PORT: %d\n", packet->BODY.MACPayload.FPort);

			uint8_t fctrl = dataToParse[idx];
			idx++;
			packet->BODY.MACPayload.FHDR.FCnt16 = parseUInt16LittleEndian(&(dataToParse[idx]));
			idx += 2;

			if (packet->BODY.MACPayload.FPort == 0) {
				lw_key.aeskey = lib.state.pDevCfg->NwkSEncKey;
			} else {
				lw_key.aeskey = lib.state.pDevCfg->AppSKey;
			}
			lw_key.in = (uint8_t *) dataToParse;
			lw_key.len = length - 4;
			lw_key.devaddr.data = packet->BODY.MACPayload.FHDR.DevAddr;

			uint32_t currFCnt32;
			lw_key.link = LW_DOWNLINK;
			bool useAFCntDwn = false;
			if (lib.state.pDevCfg->LorawanVersion >= LORAWAN_VERSION_1_1) {
				// LoRaWAN 1.1 -- separate DL counters
				if (packet->BODY.MACPayload.FPort == 0) {
					// LOG_INFO("NFCntDwn: %d\n", lib.state.pFCntCtrl->NFCntDwn);
					currFCnt32 = lib.state.pFCntCtrl->NFCntDwn;
				} else {
					// LOG_INFO("AFCntDwn: %d\n", lib.state.pFCntCtrl->AFCntDwn);
					currFCnt32 = lib.state.pFCntCtrl->AFCntDwn;
					useAFCntDwn = true;
				}
			} else {
				// LoRaWAN 1.0 -- use only one counter
				// LOG_INFO("FCntDwn: %d\n", lib.state.pFCntCtrl->NFCntDwn);
				currFCnt32 = lib.state.pFCntCtrl->NFCntDwn;
			}
			packet->BODY.MACPayload.FHDR.FCtrl.downlink.ADR = fctrl >> 7u;
			packet->BODY.MACPayload.FHDR.FCtrl.downlink.ACK = (fctrl & (1u << 5u)) >> 5u;
			packet->BODY.MACPayload.FHDR.FCtrl.downlink.FPending = (fctrl & (1u << 4u)) >> 4u;
			packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen = (fctrl & 0x0fu);


			// currFCnt32 holds the next expected FCnt for received packet (since the first FCnt is 0)
			uint16_t currFCnt32_LSB = (uint16_t) currFCnt32;
			uint16_t currFCnt32_MSB = (uint16_t) (currFCnt32 >> 16u);
//			LOG_INFO("Lobawan| counter: %cFCntDwn, current: %08x\n", (useAFCntDwn?'A':'N'), currFCnt32);
			// In LoRaWAN 1.. it's allowed to re-transmit the last downlink (due to LCTT)
			// TODO: Clarify: In LoRaWAN 1.1 retransmissions are not allowed (but we still allow a retransmission of the last packet yet!)
			// See: https://lcttbugs.lora-alliance.com/bugzilla/show_bug.cgi?id=172
			// Thus the "- 1"
			if (packet->BODY.MACPayload.FHDR.FCnt16 < currFCnt32_LSB - 1) {
				// this is either a replay or a 16bit overflow
				// we expect overflow, replays will have invalid MIC after overflow (since 32bit counter is different)
				currFCnt32_MSB++;
			}

			// LoRaWAN 1.0.x only, when
			if (lib.state.pDevCfg->LorawanVersion >= LORAWAN_VERSION_1_0) {
				const int MAX_FCNT_GAP = 16384;
				if (packet->BODY.MACPayload.FHDR.FCnt16 - currFCnt32_LSB > MAX_FCNT_GAP) {
					LOG_ERROR("LoRa| Downlink FCnt increased by more than MAX_FCNT_GAP (%d): FCnt=%d expected FCnt=%d -> drop packet\n",
							  MAX_FCNT_GAP, packet->BODY.MACPayload.FHDR.FCnt16, currFCnt32_LSB);
					LoRaWAN_DeletePacket(packet);
					return NULL;
				}
			}

			currFCnt32 = (((uint32_t) currFCnt32_MSB) << 16u) + packet->BODY.MACPayload.FHDR.FCnt16;
			lw_key.fcnt32 = currFCnt32;
//			LOG_INFO("Lobawan| FCnt16: %04x, FCnt32: %08x\n", packet->BODY.MACPayload.FHDR.FCnt16, currFCnt32);

			// calc & compare mic
			packet->MIC = parseUInt32LittleEndian(dataToParse + length - 4);
			lw_key.aeskey = lib.state.pDevCfg->SNwkSIntKey;
			lw_msg_mic(&micCalc, &lw_key);

			if (micCalc.data != packet->MIC) {    // check if mic is ok
				LOG_ERROR("LoRa| Data MIC error 0x%8X != 0x%8X (expected) -> drop packet\n", packet->MIC, micCalc.data);
				LOG_ERROR("lwKey: fCnt: %d len: %d\n", lw_key.fcnt32, lw_key.len, lw_key.devaddr);
				lorawan_logLoraPacket(packet, false);
				LoRaWAN_DeletePacket(packet);
				return NULL;
			}

			// write back counter only if MIC was correct, otherwise replay attacks could corrupt our counter
			// counter is set to next expected value
			if (useAFCntDwn) {
				lib.state.pFCntCtrl->AFCntDwn = currFCnt32 + 1;
			} else {
				lib.state.pFCntCtrl->NFCntDwn = currFCnt32 + 1;
			}

			memcpy(packet->BODY.MACPayload.FHDR.FOpts, &(dataToParse[idx]), packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen);
			if (lib.state.pDevCfg->LorawanVersion >= LORAWAN_VERSION_1_1) {
				// TODO: this only for 1.1? 1.1 spec is not specific about this, but i cannot find encryption of FOpts in 1.0
				encrypt_fopts(
						packet->BODY.MACPayload.FHDR.FOpts,
						packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen,
						lib.state.pDevCfg->NwkSEncKey,
						useAFCntDwn,
						false,
						&lw_key.devaddr,
						currFCnt32
				);
			}
			idx += packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen;


			// copy other fields & decrypt payload (if present)
			uint8_t lengthWithoutPayloadAndPort = (1 + 7 + packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen + 4);  // MHDR(1) + FHDR(7) + FHDR_OPTS(x) + MIC (4)
			if (length > lengthWithoutPayloadAndPort) {
				// skip port, we did that at the beginning:
				idx++;
				if (length == lengthWithoutPayloadAndPort + 1) { // no payload, but port
					packet->BODY.MACPayload.payloadLength = 0;
					LOG_ERROR("LoRa| warn packet with port but without payload\n");
				} else {
					packet->BODY.MACPayload.payloadLength = length - 4 - idx;

					if (packet->BODY.MACPayload.FPort == 0) {
						lw_key.aeskey = lib.state.pDevCfg->NwkSEncKey;
					} else {
						lw_key.aeskey = lib.state.pDevCfg->AppSKey;
					}
					lw_key.in = (uint8_t *) &(dataToParse[idx]);
					lw_key.len = packet->BODY.MACPayload.payloadLength;

					packet->pPayload = (uint8_t *) lib.api.malloc(packet->BODY.MACPayload.payloadLength);

					if (packet->pPayload == NULL) {
						LOG_ERROR("LoRa| LoRaWAN_UnmarshalPacket OOM!\n");
						LoRaWAN_DeletePacket(packet);
						return NULL;
					}

					// decrypt by encrypt
					if (lw_encrypt(packet->pPayload, &lw_key) <= 0) {
						LOG_ERROR("LoRaWAN_UnmarshalPacket decrypt fail\n");
						LoRaWAN_DeletePacket(packet);
						return NULL;
					}
				}

			} else { // no payload, no port, no cry
				packet->BODY.MACPayload.payloadLength = 0;
				packet->pPayload = NULL;
			}

			uint8_t fOptsLen = packet->BODY.MACPayload.FHDR.FCtrl.downlink.FOptsLen;
			uint8_t fPort = packet->BODY.MACPayload.FPort;
			uint8_t payloadLen = packet->BODY.MACPayload.payloadLength;

			// LoRaWAN 1.1 - 4.3.1.6 Frame options
			// 677 MAC commands cannot be simultaneously present in the payload field and the frame
			// 678 options field. Should this occur, the device SHALL ignore the frame.
			// Do not handle Port 0 with fOpts and payload! -> Required by LCTT
			if (fPort == 0 && fOptsLen > 0 && payloadLen > 0) {
				LOG_ERROR("LoRa| Port 0: fOptsLen & payloadLen set -> drop packet\n");
				LoRaWAN_DeletePacket(packet);
				return NULL;
			}

			return packet;

		case MTYPE_JOIN_ACCEPT:

			// MHDR(1) + [sizeof(JoinAccept_t)(12) + optional CFlist(16)] + MIC(4), max len: 33 byte
			if (length == 17) {
				packet->BODY.JoinAccept.hasCFlist = false;
			} else if (length == 17 + 16) {
				packet->BODY.JoinAccept.hasCFlist = true; // optional frequency list send by network server
			} else {
				LOG_ERROR("LoRa| Got JoinRequest with unexpected length -> drop packet\n");
				LoRaWAN_DeletePacket(packet);
				return NULL;
			}

			// (1) beside MHDR whole the message is encrypted -> decrypt it first
			uint8_t decryptedData[33]; // temp buffer
			lw_key.aeskey = lib.state.pDevCfg->NwkKey;  // TODO: for rejoins, this uses JSEncKey
			lw_key.in = dataToParse + 1;  // skip MHDR
			lw_key.len = length - 1;
			decryptedData[0] = dataToParse[0]; // MHDR can be copied as it's not encrypted
			int pl_len = lw_join_decrypt(decryptedData + 1, &lw_key);
/*			LOG_INFO("Lobawan: uncryp: ");
			for (int i=0; i<length; i++) {
				LOG_INFO("%02x", decryptedData[i]);
			}
			LOG_INFO("\n");*/

			if (pl_len <= 0) {
				LOG_ERROR("LoRa| Can't decrypt JoinAccept\n");
				LoRaWAN_DeletePacket(packet);
				return NULL;
			}

			// (1.5) check OptNeg ahead of MIC to know if to use LoRaWAN 1.0 or 1.1:
			bool useVersion11 = ((decryptedData[11] & 0x80u) >> 7u);

			// (2) check MIC
			packet->MIC = parseUInt32LittleEndian(decryptedData + length - 4);
			if (useVersion11) {
				// LOG_INFO("v1.1\n");
				// JoinReqType | JoinEUI | DevNonce | MHDR | JoinNonce | NetID | DevAddr | DLSettings | RxDelay | CFList
				uint8_t bb[48];  // length is 17 or 33, +11 -4 -> 40 -> 48 for padding
				memset(bb, 0, 48);
				bb[0] = 0xff;  // TODO: this is for join - add rejoin requests
				memcpy(bb + 1, lib.state.pDevCfg->JoinEUI, 8);
				convertInPlaceEUI64bufLittleEndian(bb + 1);
				bb[9] = lib.state.pDevCfg->DevNonce & 0xffu;  // TODO: is this mixed up?
				bb[10] = lib.state.pDevCfg->DevNonce >> 8u;
//				bb[10] = lib.state.pDevCfg->DevNonce & 0xffu;  // TODO: is this mixed up?
//				bb[9] = lib.state.pDevCfg->DevNonce >> 8u;
				memcpy(bb + 11, decryptedData, length - 4);
				lw_key.aeskey = lib.state.pDevCfg->JSIntKey;
				lw_key.in = bb;
				lw_key.len = 11 + length - 4; // skip MIC
				lw_join_mic(&micCalc, &lw_key);
				// TODO: does this work?
			} else {
				// LOG_INFO("v1.0\n");
				lw_key.aeskey = lib.state.pDevCfg->NwkKey;
				lw_key.in = decryptedData;
				lw_key.len = length - 4; // skip MIC
				lw_join_mic(&micCalc, &lw_key);
			}
			// LOG_INFO("Lobawan| MIC: calc=%08x, pack=%08x\n", micCalc.data, packet->MIC);
			if (micCalc.data != packet->MIC) {    // check if mic is ok
				LOG_ERROR("LoRa| Join accept mic error -> drop packet\n");
				LoRaWAN_DeletePacket(packet);
				return NULL;
			}

			// (3) parse fields
			idx = 1; // skip already parsed MHDR
			packet->BODY.JoinAccept.JoinNonce = decryptedData[idx++];
			packet->BODY.JoinAccept.JoinNonce |= ((uint32_t) decryptedData[idx++] << 8u);
			packet->BODY.JoinAccept.JoinNonce |= ((uint32_t) decryptedData[idx++] << 16u);

			packet->BODY.JoinAccept.HomeNetID = decryptedData[idx++];
			packet->BODY.JoinAccept.HomeNetID |= ((uint32_t) decryptedData[idx++] << 8u);
			packet->BODY.JoinAccept.HomeNetID |= ((uint32_t) decryptedData[idx++] << 16u);

			packet->BODY.JoinAccept.DevAddr = parseUInt32LittleEndian(&(decryptedData[idx]));
			idx += 4;
			packet->BODY.JoinAccept.DLsettings.OptNeg = ((decryptedData[idx] & 0x80u) >> 7u);
			packet->BODY.JoinAccept.DLsettings.Rx1DRoffset = ((decryptedData[idx] & 0x70u) >> 4u);
			packet->BODY.JoinAccept.DLsettings.Rx2DR = (decryptedData[idx] & 0x0fu);
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
			if (packet->BODY.JoinAccept.DLsettings.OptNeg) {
				// LoRaWAN v1.1
				lw_skey_seed_11_t lw_skey_seed;
				lw_skey_seed.nwkkey = lib.state.pDevCfg->NwkKey;
				lw_skey_seed.appkey = lib.state.pDevCfg->AppKey;
				lw_skey_seed.jnonce.data = packet->BODY.JoinAccept.JoinNonce;
				lw_skey_seed.joineui = lib.state.pDevCfg->JoinEUI;
				lw_skey_seed.dnonce.data = lib.state.pDevCfg->DevNonce;
				lw_get_skeys_11(
						packet->BODY.JoinAccept.derived_fnwksintkey,
						packet->BODY.JoinAccept.derived_snwksintkey,
						packet->BODY.JoinAccept.derived_nwksenckey,
						packet->BODY.JoinAccept.derived_appskey,
						&lw_skey_seed); // todo maybe add as special "payload" to packet?
				packet->BODY.JoinAccept.usesVersion11 = true;
			} else {
				lw_skey_seed_t lw_skey_seed;
				lw_skey_seed.aeskey = lib.state.pDevCfg->NwkKey;
				lw_skey_seed.anonce.data = packet->BODY.JoinAccept.JoinNonce;
				lw_skey_seed.netid.data = packet->BODY.JoinAccept.HomeNetID;
				lw_skey_seed.dnonce.data = lib.state.pDevCfg->DevNonce;
				lw_get_skeys(packet->BODY.JoinAccept.derived_fnwksintkey, packet->BODY.JoinAccept.derived_appskey,
							 &lw_skey_seed); // todo maybe add as special "payload" to packet?
				packet->BODY.JoinAccept.usesVersion11 = false;
			}

			// app should adjust nwkskey, appskey, devAdr, netId, appnounce
			return packet;

		default:
			LOG_ERROR("LoRa| unknown MHDR type -> drop packet\n");
			LoRaWAN_DeletePacket(packet);
			return NULL;
	}

	return packet;
}

// Like LoRaWAN_NewPacket but takes a marshaled packet as input
// MUST be freed with LoRaWAN_DeletePacket
// data is the raw packet as produced by LoRaWAN_MarshalPacket
lorawan_packet_t *LoRaWAN_UnmarshalPacket(const uint8_t *dataToParse, uint8_t length) { // todo add keys as parameter
	return LoRaWAN_UnmarshalPacketFor(dataToParse, length, 0);
}
