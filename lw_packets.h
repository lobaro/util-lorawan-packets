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

#ifndef DRV_LOBARO_LW_PACKETS_H_
#define DRV_LOBARO_LW_PACKETS_H_

#include <stdbool.h>
#include <stddef.h>
#include <github.com/lobaro/c-utils/datetime.h>

#include "lw_state.h"
// not supported yet!
// yet only used to throw compiler warning at important positons
#define USE_LORAWAN_1_1  (1)

#ifdef __cplusplus
extern "C" {
#endif

// LoRaWAN MAC header (MHDR)
typedef enum {
	MTYPE_JOIN_REQUEST = 0,
	MTYPE_JOIN_ACCEPT,
	MTYPE_UNCONFIRMED_DATA_UP,
	MTYPE_UNCONFIRMED_DATA_DOWN,
	MTYPE_CONFIRMED_DATA_UP,
	MTYPE_CONFIRMED_DATA_DOWN,
	MTYPE_REJOIN_REQUEST,
	MTYPE_PROPRIETARY = 0b111
} MHDR_Mtype_t;

typedef enum {
	LORAWAN_R1 = 0,
} MHDR_LoRaWAN_MajorVersion_t;

typedef struct {
	MHDR_Mtype_t type;
	MHDR_LoRaWAN_MajorVersion_t version;
} MHDR_t;

typedef enum {
	ResetInd = 0x01, // Send by Device (LoRaWAN 1.1)
	ResetConf = 0x01,
	// From here LoRaWAN 1.0
	LinkCheckReq = 0x02, // Send by Device
	LinkCheckAns = 0x02,
	LinkADRReq = 0x03,
	LinkADRAns = 0x03,
	DutyCycleReq = 0x04,
	DutyCycleAns = 0x04,
	RXParamSetupReq = 0x05,
	RXParamSetupAns = 0x05,
	DevStatusReq = 0x06,
	DevStatusAns = 0x06,
	NewChannelReq = 0x07,
	NewChannelAns = 0x07,
	RXTimingSetupReq = 0x08,
	RXTimingSetupAns = 0x08,
	// From here LoRaWAN 1.1
	TxParamSetupReq = 0x09,
	TxParamSetupAns = 0x09,
	DlChannelReq = 0x0A,
	DlChannelAns = 0x0A,
	RekeyInd = 0x0B, // Send by Device
	RekeyConf = 0x0B,
	ADRParamSetupReq = 0x0C,
	ADRParamSetupAns = 0x0C,
	DeviceTimeReq = 0x0D, // Send by Device
	DeviceTimeAns = 0x0D,
	ForceRejoinReq = 0x0E,
	RejoinParamSetupReq = 0x0F,
	RejoinParamSetupAns = 0x0F,
	// [1.1:2359] MAC commands for Class C devices:
	DeviceModeInd = 0x20,  // Send by Device
	DeviceModeConf = 0x20,
	// 0x80 .. 0xFF Reserved for proprietary network command extensions
} Lorawan_MacCommand_t; // Corresponds to the CID


// part of FHDR_FCtrl_t
typedef struct {
	uint8_t ADR :1;        // Adaptive data rate control bit
	uint8_t RFU :1; // Reserved for Future Use
	uint8_t ACK :1;
	uint8_t FPending :1;
	uint8_t FOptsLen :4;
} FHDR_FCtrl_downlink_t;

// part of FHDR_FCtrl_t
typedef struct {
	uint8_t ADR :1;        // Adaptive data rate control bit
	uint8_t ADRACKReq :1;
	uint8_t ACK :1;
	uint8_t ClassB :1;
	uint8_t FOptsLen :4;
} FHDR_FCtrl_uplink_t;

// part of FHDR_t
typedef union {
	FHDR_FCtrl_downlink_t downlink;
	FHDR_FCtrl_uplink_t uplink;
} FHDR_FCtrl_t;

// part of MACPayload_t
typedef struct {
	uint32_t DevAddr;
	FHDR_FCtrl_t FCtrl;
	uint16_t FCnt16; // only LSB of 32 bit frame Counter
	uint8_t FOpts[16]; // Max 15 bytes! Any reason for 16 byte? Alignment?
} FHDR_t;

// part of MsgBody_t (union)
typedef struct {
	FHDR_t FHDR;            // LoRaWAN Frame header
	//uint8_t* payload; 	// optional, NOTE: payload pointer is in lorawan_packet_t struct
	uint8_t payloadLength;
	uint8_t FPort;            // must be set if payload is present else optional
} MACPayload_t;

// part of MsgBody_t (union)
typedef struct {
	uint8_t joinEUI[8]; // before LoRaWAN1.1 this was also called the appEUI
	uint8_t devEUI[8];
	uint16_t devnonce; // must be random for each join request
} JoinRequest_t;

// part of JoinAccept_t
typedef struct {
	uint8_t Rx2DR :4;
	uint8_t Rx1DRoffset :3;
	uint8_t OptNeg :1;
} DLsettings_t;

// part of JoinAccept_t
typedef struct {
	uint8_t FreqCH4[3];
	uint8_t FreqCH5[3];
	uint8_t FreqCH6[3];
	uint8_t FreqCH7[3];
	uint8_t FreqCH8[3];
	// + RFU (1 Byte)
} CFlist_t;

// part of MsgBody_t (union)
typedef struct {
	uint32_t JoinNonce;            // 24 bit (3 Byte), server nonce
	uint32_t HomeNetID;            // 24 bit (3 Byte), network identifier
	uint32_t DevAddr;                // 32 bit (4 Byte), end-device address
	DLsettings_t DLsettings;        // 8 bit (1 Byte), providing some of the downlink parameter
	uint8_t RxDelay;                // 8 bit (1 Byte), the delay between TX and RX
	// total: 12
	CFlist_t CFlist;                // 16 byte, optional list of network parameters (e.g. frequencies for EU868)
	// total: 12+16=28
	bool hasCFlist;
	bool usesVersion11;

	uint8_t derived_fnwksintkey[16];    // todo use malloc instead?
	uint8_t derived_snwksintkey[16];
	uint8_t derived_nwksenckey[16];
	uint8_t derived_appskey[16];
} JoinAccept_t;

typedef union {
	MACPayload_t MACPayload;
	JoinRequest_t JoinRequest;
	JoinAccept_t JoinAccept; // For Join-Accept, the MIC field is encrypted with the payload and is not a separate field
} MsgBody_t;

typedef struct {
	Time_t DeviceTime; // From DeviceTimeAns, 0 if not set
} DecodedMacResponse_t;

typedef enum {
	LORAWAN_SwitchModeClassA = 1u << 0u,
//	LORAWAN_SwitchModeClassB = 1u << 1u,
	LORAWAN_SwitchModeClassC = 1u << 2u,
	LORAWAN_SwitchMode = 0b101, // any of the three above
} Lorawan_PostAction_t;

typedef struct {
	uint16_t confFCnt;
	uint8_t txDr;
	uint8_t txCh;
} lorawan_uplink_meta_t;

// Complete PHYPayload packet
typedef struct {
	// user mutable fields
	MHDR_t MHDR;        // LoRaWAN MAC header (1 Byte)
	MsgBody_t BODY;    // MHDR defines either MACPayload OR Join/Rejoin-Request OR Join-Accept (then MIC encrypted inside payload)

	// calculated field
	uint32_t MIC;

	// internal control flag
	// Length is saved in BODY.MACPayload.payloadLength
	uint8_t* pPayload;    // != NULL if the body contains some memory that must be freed (maybe the case for dataUp/dataDown msg)
	// this ensures a graceful delete of packet independent of MHDR type

	DecodedMacResponse_t MacResp;  // Field to store decoded mac responses for the application

	uint8_t PostTransmissionAction;  // Indicator for actions/changes that must be executed after the successful transmission/reception of a message

	// information needed for 1.1 during message marshaling
	lorawan_uplink_meta_t UplinkMeta;
} lorawan_packet_t;

// external function dependencies
// function pointers maybe NULL if using the defaults
typedef struct {
	void* (* malloc)(size_t size);                // default: malloc (stdlib.h)
	void (* free)(void* buf);                    // default: free (stdlib.h)
	void (* LogInfo)(const char* format, ...);    // default: "logNothingDummy()" function
	void (* LogError)(const char* format, ...); // default: "logNothingDummy()" function
} lwPackets_api_t;

// external state dependencies
// these parameters should be known by your LoRaWAN stack which uses this lib
// maybe a simple wrapper is needed
typedef struct {
	Lorawan_fcnt_t* pFCntCtrl; // pointer to external App netCtrl structure (see lw_state.h)
	Lorawan_devCfg_t* pDevCfg;  // pointer to external App devCtrl structure (see lw_state.h)
} lwPackets_state_t;

// Setup external dependencies
// must be called at least once before usage
void LoRaWAN_PacketsUtil_Init(lwPackets_api_t api, lwPackets_state_t state);

// LoRaWAN packet parser
lorawan_packet_t* LoRaWAN_UnmarshalPacket(const uint8_t* dataToParse, uint8_t length);   // must  be deleted again!
lorawan_packet_t* LoRaWAN_UnmarshalPacketFor(const uint8_t* dataToParse, uint8_t length, uint32_t addr);   // must  be deleted again!

// payload: optional external payload buffer with data to be copied into new packet
// length: size of external payload
// result: lorawan_packet_t* which must be deleted again by user!
lorawan_packet_t* LoRaWAN_NewPacket(const uint8_t* payload, uint8_t length);    // must  be deleted again!
uint8_t LoRaWAN_MarshalPacket(lorawan_packet_t* packet, uint8_t* buffer, uint8_t bufferSize);

void LoRaWAN_DeletePacket(lorawan_packet_t* packet);
void LoRaWAN_DeletePayload(lorawan_packet_t* packet);

#ifdef __cplusplus
}
#endif

#endif
