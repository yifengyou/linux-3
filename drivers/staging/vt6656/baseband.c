/*
 * Copyright (c) 1996, 2003 VIA Networking Technologies, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * File: baseband.c
 *
 * Purpose: Implement functions to access baseband
 *
 * Author: Jerry Chen
 *
 * Date: Jun. 5, 2002
 *
 * Functions:
 *      BBuGetFrameTime        - Calculate data frame transmitting time
 *      BBvCalculateParameter   - Calculate PhyLength, PhyService and Phy Signal parameter for baseband Tx
 *      BBbVT3184Init          - VIA VT3184 baseband chip init code
 *
 * Revision History:
 *
 *
 */

#include "tmacro.h"
#include "tether.h"
#include "mac.h"
#include "baseband.h"
#include "rf.h"
#include "usbpipe.h"
#include "datarate.h"

static u8 abyVT3184_AGC[] = {
    0x00,   //0
    0x00,   //1
    0x02,   //2
    0x02,   //3  //RobertYu:20060505, 0x04,   //3
    0x04,   //4
    0x04,   //5  //RobertYu:20060505, 0x06,   //5
    0x06,   //6
    0x06,   //7
    0x08,   //8
    0x08,   //9
    0x0A,   //A
    0x0A,   //B
    0x0C,   //C
    0x0C,   //D
    0x0E,   //E
    0x0E,   //F
    0x10,   //10
    0x10,   //11
    0x12,   //12
    0x12,   //13
    0x14,   //14
    0x14,   //15
    0x16,   //16
    0x16,   //17
    0x18,   //18
    0x18,   //19
    0x1A,   //1A
    0x1A,   //1B
    0x1C,   //1C
    0x1C,   //1D
    0x1E,   //1E
    0x1E,   //1F
    0x20,   //20
    0x20,   //21
    0x22,   //22
    0x22,   //23
    0x24,   //24
    0x24,   //25
    0x26,   //26
    0x26,   //27
    0x28,   //28
    0x28,   //29
    0x2A,   //2A
    0x2A,   //2B
    0x2C,   //2C
    0x2C,   //2D
    0x2E,   //2E
    0x2E,   //2F
    0x30,   //30
    0x30,   //31
    0x32,   //32
    0x32,   //33
    0x34,   //34
    0x34,   //35
    0x36,   //36
    0x36,   //37
    0x38,   //38
    0x38,   //39
    0x3A,   //3A
    0x3A,   //3B
    0x3C,   //3C
    0x3C,   //3D
    0x3E,   //3E
    0x3E    //3F
};

static u8 abyVT3184_AL2230[] = {
        0x31,//00
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        0x00,
        0x00,
        0x70,
        0x45,//tx   //0x64 for FPGA
        0x2A,
        0x76,
        0x00,
        0x00,
        0x80,
        0x00,
        0x00,//10
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x8e,       //RobertYu:20060522, //0x8d,
        0x0a,       //RobertYu:20060515, //0x09,
        0x00,
        0x00,
        0x00,
        0x00,//20
        0x00,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x0c,       //RobertYu:20060522, //0x10,
        0x26,//30
        0x5b,
        0x00,
        0x00,
        0x00,
        0x00,
        0xaa,
        0xaa,
        0xff,
        0xff,
        0x79,
        0x00,
        0x00,
        0x0b,
        0x48,
        0x04,
        0x00,//40
        0x08,
        0x00,
        0x08,
        0x08,
        0x14,
        0x05,
        0x09,
        0x00,
        0x00,
        0x00,
        0x00,
        0x09,
        0x73,
        0x00,
        0xc5,
        0x00,//50   //RobertYu:20060505, //0x15,//50
        0x19,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xd0,       //RobertYu:20060505, //0xb0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xe4,//60
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x98,
        0x0a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,       //0x80 for FPGA
        0x03,
        0x01,
        0x00,
        0x00,//70
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x8c,//80
        0x01,
        0x09,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x08,
        0x00,
        0x1f,       //RobertYu:20060516, //0x0f,
        0xb7,
        0x88,
        0x47,
        0xaa,
        0x00,       //RobertYu:20060505, //0x02,
        0x20,//90   //RobertYu:20060505, //0x22,//90
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xeb,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,//a0
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x18,
        0x00,
        0x00,
        0x00,
        0x00,
        0x15,       //RobertYu:20060516, //0x00,
        0x00,
        0x18,
        0x38,//b0
        0x30,
        0x00,
        0x00,
        0xff,
        0x0f,
        0xe4,
        0xe2,
        0x00,
        0x00,
        0x00,
        0x03,
        0x01,
        0x00,
        0x00,
        0x00,
        0x18,//c0
        0x20,
        0x07,
        0x18,
        0xff,
        0xff,       //RobertYu:20060509, //0x2c,
        0x0e,       //RobertYu:20060530, //0x0c,
        0x0a,
        0x0e,
        0x00,       //RobertYu:20060505, //0x01,
        0x82,       //RobertYu:20060516, //0x8f,
        0xa7,
        0x3c,
        0x10,
        0x30,       //RobertYu:20060627, //0x0b,
        0x05,       //RobertYu:20060516, //0x25,
        0x40,//d0
        0x12,
        0x00,
        0x00,
        0x10,
        0x28,
        0x80,
        0x2A,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,//e0
        0xf3,       //RobertYu:20060516, //0xd3,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x12,       //RobertYu:20060627, //0x10,
        0x00,
        0xf4,
        0x00,
        0xff,
        0x79,
        0x20,
        0x30,
        0x05,       //RobertYu:20060516, //0x0c,
        0x00,//f0
        0x3e,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00
};

//{{RobertYu:20060515, new BB setting for VT3226D0
static u8 abyVT3184_VT3226D0[] = {
        0x31,//00
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        0x00,
        0x00,
        0x70,
        0x45,//tx   //0x64 for FPGA
        0x2A,
        0x76,
        0x00,
        0x00,
        0x80,
        0x00,
        0x00,//10
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x8e,       //RobertYu:20060525, //0x8d,
        0x0a,       //RobertYu:20060515, //0x09,
        0x00,
        0x00,
        0x00,
        0x00,//20
        0x00,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x0c,       //RobertYu:20060525, //0x10,
        0x26,//30
        0x5b,
        0x00,
        0x00,
        0x00,
        0x00,
        0xaa,
        0xaa,
        0xff,
        0xff,
        0x79,
        0x00,
        0x00,
        0x0b,
        0x48,
        0x04,
        0x00,//40
        0x08,
        0x00,
        0x08,
        0x08,
        0x14,
        0x05,
        0x09,
        0x00,
        0x00,
        0x00,
        0x00,
        0x09,
        0x73,
        0x00,
        0xc5,
        0x00,//50   //RobertYu:20060505, //0x15,//50
        0x19,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xd0,       //RobertYu:20060505, //0xb0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xe4,//60
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x98,
        0x0a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,       //0x80 for FPGA
        0x03,
        0x01,
        0x00,
        0x00,//70
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x8c,//80
        0x01,
        0x09,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x08,
        0x00,
        0x1f,       //RobertYu:20060515, //0x0f,
        0xb7,
        0x88,
        0x47,
        0xaa,
        0x00,       //RobertYu:20060505, //0x02,
        0x20,//90   //RobertYu:20060505, //0x22,//90
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xeb,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,//a0
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x18,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x18,
        0x38,//b0
        0x30,
        0x00,
        0x00,
        0xff,
        0x0f,
        0xe4,
        0xe2,
        0x00,
        0x00,
        0x00,
        0x03,
        0x01,
        0x00,
        0x00,
        0x00,
        0x18,//c0
        0x20,
        0x07,
        0x18,
        0xff,
        0xff,       //RobertYu:20060509, //0x2c,
        0x10,       //RobertYu:20060525, //0x0c,
        0x0a,
        0x0e,
        0x00,       //RobertYu:20060505, //0x01,
        0x84,       //RobertYu:20060525, //0x8f,
        0xa7,
        0x3c,
        0x10,
        0x24,       //RobertYu:20060627, //0x18,
        0x05,       //RobertYu:20060515, //0x25,
        0x40,//d0
        0x12,
        0x00,
        0x00,
        0x10,
        0x28,
        0x80,
        0x2A,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,//e0
        0xf3,       //RobertYu:20060515, //0xd3,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
        0x10,       //RobertYu:20060627, //0x0e,
        0x00,
        0xf4,
        0x00,
        0xff,
        0x79,
        0x20,
        0x30,
        0x08,       //RobertYu:20060515, //0x0c,
        0x00,//f0
        0x3e,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
};

static const u16 awcFrameTime[MAX_RATE] =
{10, 20, 55, 110, 24, 36, 48, 72, 96, 144, 192, 216};

/*
 * Description: Calculate data frame transmitting time
 *
 * Parameters:
 *  In:
 *	preamble_type	- Preamble Type
 *	pkt_type	- PK_TYPE_11A, PK_TYPE_11B, PK_TYPE_11GB, PK_TYPE_11GA
 *	frame_length	- Baseband Type
 *	tx_rate		- Tx Rate
 *  Out:
 *
 * Return Value: FrameTime
 *
 */
unsigned int BBuGetFrameTime(u8 preamble_type, u8 pkt_type,
	unsigned int frame_length, u16 tx_rate)
{
	unsigned int frame_time;
	unsigned int preamble;
	unsigned int tmp;
	unsigned int rate = 0;

	if (tx_rate > RATE_54M)
		return 0;

	rate = (unsigned int)awcFrameTime[tx_rate];

	if (tx_rate <= 3) {
		if (preamble_type == 1)
			preamble = 96;
		else
			preamble = 192;

		frame_time = (frame_length * 80) / rate;
		tmp = (frame_time * rate) / 80;

		if (frame_length != tmp)
			frame_time++;

		return preamble + frame_time;
	} else {
		frame_time = (frame_length * 8 + 22) / rate;
		tmp = ((frame_time * rate) - 22) / 8;

		if (frame_length != tmp)
			frame_time++;

		frame_time = frame_time * 4;

		if (pkt_type != PK_TYPE_11A)
			frame_time += 6;

		return 20 + frame_time;
	}
}

/*
 * Description: Calculate Length, Service, and Signal fields of Phy for Tx
 *
 * Parameters:
 *  In:
 *      priv         - Device Structure
 *      frame_length   - Tx Frame Length
 *      tx_rate           - Tx Rate
 *  Out:
 *	struct vnt_phy_field *phy
 * 			- pointer to Phy Length field
 *			- pointer to Phy Service field
 * 			- pointer to Phy Signal field
 *
 * Return Value: none
 *
 */
void BBvCalculateParameter(struct vnt_private *priv, u32 frame_length,
	u16 tx_rate, u8 pkt_type, struct vnt_phy_field *phy)
{
	u32 bit_count;
	u32 count = 0;
	u32 tmp;
	int ext_bit;
	u8 preamble_type = priv->byPreambleType;

	bit_count = frame_length * 8;
	ext_bit = false;

	switch (tx_rate) {
	case RATE_1M:
		count = bit_count;

		phy->signal = 0x00;

		break;
	case RATE_2M:
		count = bit_count / 2;

		if (preamble_type == 1)
			phy->signal = 0x09;
		else
			phy->signal = 0x01;

		break;
	case RATE_5M:
		count = (bit_count * 10) / 55;
		tmp = (count * 55) / 10;

		if (tmp != bit_count)
			count++;

		if (preamble_type == 1)
			phy->signal = 0x0a;
		else
			phy->signal = 0x02;

		break;
	case RATE_11M:
		count = bit_count / 11;
		tmp = count * 11;

		if (tmp != bit_count) {
			count++;

			if ((bit_count - tmp) <= 3)
				ext_bit = true;
		}

		if (preamble_type == 1)
			phy->signal = 0x0b;
		else
			phy->signal = 0x03;

		break;
	case RATE_6M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9b;
		else
			phy->signal = 0x8b;

		break;
	case RATE_9M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9f;
		else
			phy->signal = 0x8f;

		break;
	case RATE_12M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9a;
		else
			phy->signal = 0x8a;

		break;
	case RATE_18M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9e;
		else
			phy->signal = 0x8e;

		break;
	case RATE_24M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x99;
		else
			phy->signal = 0x89;

		break;
	case RATE_36M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9d;
		else
			phy->signal = 0x8d;

		break;
	case RATE_48M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x98;
		else
			phy->signal = 0x88;

		break;
	case RATE_54M:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9c;
		else
			phy->signal = 0x8c;
		break;
	default:
		if (pkt_type == PK_TYPE_11A)
			phy->signal = 0x9c;
		else
			phy->signal = 0x8c;
		break;
	}

	if (pkt_type == PK_TYPE_11B) {
		phy->service = 0x00;
		if (ext_bit)
			phy->service |= 0x80;
		phy->len = cpu_to_le16((u16)count);
	} else {
		phy->service = 0x00;
		phy->len = cpu_to_le16((u16)frame_length);
	}
}

/*
 * Description: Set Antenna mode
 *
 * Parameters:
 *  In:
 *	priv		- Device Structure
 *	antenna_mode	- Antenna Mode
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void BBvSetAntennaMode(struct vnt_private *priv, u8 antenna_mode)
{
	switch (antenna_mode) {
	case ANT_TXA:
	case ANT_TXB:
		break;
	case ANT_RXA:
		priv->byBBRxConf &= 0xFC;
		break;
	case ANT_RXB:
		priv->byBBRxConf &= 0xFE;
		priv->byBBRxConf |= 0x02;
		break;
	}

	vnt_control_out(priv, MESSAGE_TYPE_SET_ANTMD,
		(u16)antenna_mode, 0, 0, NULL);
}

/*
 * Description: Set Antenna mode
 *
 * Parameters:
 *  In:
 *      pDevice          - Device Structure
 *      byAntennaMode    - Antenna Mode
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */

int BBbVT3184Init(struct vnt_private *priv)
{
	int status;
	u16 length;
	u8 *addr;
	u8 *agc;
	u16 length_agc;
	u8 array[256];
	u8 data;

	status = vnt_control_in(priv, MESSAGE_TYPE_READ, 0,
		MESSAGE_REQUEST_EEPROM, EEP_MAX_CONTEXT_SIZE,
						priv->abyEEPROM);
	if (status != STATUS_SUCCESS)
		return false;

	/* zonetype initial */
	priv->byOriginalZonetype = priv->abyEEPROM[EEP_OFS_ZONETYPE];

	if (priv->config_file.ZoneType >= 0) {
		if ((priv->config_file.ZoneType == 0) &&
			(priv->abyEEPROM[EEP_OFS_ZONETYPE] != 0x00)) {
			priv->abyEEPROM[EEP_OFS_ZONETYPE] = 0;
			priv->abyEEPROM[EEP_OFS_MAXCHANNEL] = 0x0B;

			dev_dbg(&priv->usb->dev, "Init Zone Type :USA\n");
		} else if ((priv->config_file.ZoneType == 1) &&
			(priv->abyEEPROM[EEP_OFS_ZONETYPE] != 0x01)) {
			priv->abyEEPROM[EEP_OFS_ZONETYPE] = 0x01;
			priv->abyEEPROM[EEP_OFS_MAXCHANNEL] = 0x0D;

			dev_dbg(&priv->usb->dev, "Init Zone Type :Japan\n");
		} else if ((priv->config_file.ZoneType == 2) &&
			(priv->abyEEPROM[EEP_OFS_ZONETYPE] != 0x02)) {
			priv->abyEEPROM[EEP_OFS_ZONETYPE] = 0x02;
			priv->abyEEPROM[EEP_OFS_MAXCHANNEL] = 0x0D;

			dev_dbg(&priv->usb->dev, "Init Zone Type :Europe\n");
		} else {
			if (priv->config_file.ZoneType !=
					priv->abyEEPROM[EEP_OFS_ZONETYPE])
				printk("zonetype in file[%02x]\
					 mismatch with in EEPROM[%02x]\n",
					priv->config_file.ZoneType,
					priv->abyEEPROM[EEP_OFS_ZONETYPE]);
			else
				printk("Read Zonetype file success,\
					use default zonetype setting[%02x]\n",
					priv->config_file.ZoneType);
		}
	}

	if (!priv->bZoneRegExist)
		priv->byZoneType = priv->abyEEPROM[EEP_OFS_ZONETYPE];

	priv->byRFType = priv->abyEEPROM[EEP_OFS_RFTYPE];

	dev_dbg(&priv->usb->dev, "Zone Type %x\n", priv->byZoneType);

	dev_dbg(&priv->usb->dev, "RF Type %d\n", priv->byRFType);

	if ((priv->byRFType == RF_AL2230) ||
				(priv->byRFType == RF_AL2230S)) {
		priv->byBBRxConf = abyVT3184_AL2230[10];
		length = sizeof(abyVT3184_AL2230);
		addr = abyVT3184_AL2230;
		agc = abyVT3184_AGC;
		length_agc = sizeof(abyVT3184_AGC);

		priv->abyBBVGA[0] = 0x1C;
		priv->abyBBVGA[1] = 0x10;
		priv->abyBBVGA[2] = 0x0;
		priv->abyBBVGA[3] = 0x0;
		priv->ldBmThreshold[0] = -70;
		priv->ldBmThreshold[1] = -48;
		priv->ldBmThreshold[2] = 0;
		priv->ldBmThreshold[3] = 0;
	} else if (priv->byRFType == RF_AIROHA7230) {
		priv->byBBRxConf = abyVT3184_AL2230[10];
		length = sizeof(abyVT3184_AL2230);
		addr = abyVT3184_AL2230;
		agc = abyVT3184_AGC;
		length_agc = sizeof(abyVT3184_AGC);

		addr[0xd7] = 0x06;

		priv->abyBBVGA[0] = 0x1c;
		priv->abyBBVGA[1] = 0x10;
		priv->abyBBVGA[2] = 0x0;
		priv->abyBBVGA[3] = 0x0;
		priv->ldBmThreshold[0] = -70;
		priv->ldBmThreshold[1] = -48;
		priv->ldBmThreshold[2] = 0;
		priv->ldBmThreshold[3] = 0;
	} else if ((priv->byRFType == RF_VT3226) ||
			(priv->byRFType == RF_VT3226D0)) {
		priv->byBBRxConf = abyVT3184_VT3226D0[10];
		length = sizeof(abyVT3184_VT3226D0);
		addr = abyVT3184_VT3226D0;
		agc = abyVT3184_AGC;
		length_agc = sizeof(abyVT3184_AGC);

		priv->abyBBVGA[0] = 0x20;
		priv->abyBBVGA[1] = 0x10;
		priv->abyBBVGA[2] = 0x0;
		priv->abyBBVGA[3] = 0x0;
		priv->ldBmThreshold[0] = -70;
		priv->ldBmThreshold[1] = -48;
		priv->ldBmThreshold[2] = 0;
		priv->ldBmThreshold[3] = 0;
		/* Fix VT3226 DFC system timing issue */
		MACvRegBitsOn(priv, MAC_REG_SOFTPWRCTL2, SOFTPWRCTL_RFLEOPT);
	} else if ((priv->byRFType == RF_VT3342A0)) {
		priv->byBBRxConf = abyVT3184_VT3226D0[10];
		length = sizeof(abyVT3184_VT3226D0);
		addr = abyVT3184_VT3226D0;
		agc = abyVT3184_AGC;
		length_agc = sizeof(abyVT3184_AGC);

		priv->abyBBVGA[0] = 0x20;
		priv->abyBBVGA[1] = 0x10;
		priv->abyBBVGA[2] = 0x0;
		priv->abyBBVGA[3] = 0x0;
		priv->ldBmThreshold[0] = -70;
		priv->ldBmThreshold[1] = -48;
		priv->ldBmThreshold[2] = 0;
		priv->ldBmThreshold[3] = 0;
		/* Fix VT3226 DFC system timing issue */
		MACvRegBitsOn(priv, MAC_REG_SOFTPWRCTL2, SOFTPWRCTL_RFLEOPT);
	} else {
		return true;
	}

	memcpy(array, addr, length);

	vnt_control_out(priv, MESSAGE_TYPE_WRITE, 0,
		MESSAGE_REQUEST_BBREG, length, array);

	memcpy(array, agc, length_agc);

	vnt_control_out(priv, MESSAGE_TYPE_WRITE, 0,
		MESSAGE_REQUEST_BBAGC, length_agc, array);

	if ((priv->byRFType == RF_VT3226) ||
		(priv->byRFType == RF_VT3342A0)) {
		vnt_control_out_u8(priv, MESSAGE_REQUEST_MACREG,
						MAC_REG_ITRTMSET, 0x23);
		MACvRegBitsOn(priv, MAC_REG_PAPEDELAY, 0x01);
	} else if (priv->byRFType == RF_VT3226D0) {
		vnt_control_out_u8(priv, MESSAGE_REQUEST_MACREG,
						MAC_REG_ITRTMSET, 0x11);
		MACvRegBitsOn(priv, MAC_REG_PAPEDELAY, 0x01);
	}

	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x04, 0x7f);
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0d, 0x01);

	vnt_rf_table_download(priv);

	/* Fix for TX USB resets from vendors driver */
	vnt_control_in(priv, MESSAGE_TYPE_READ, USB_REG4,
		MESSAGE_REQUEST_MEM, sizeof(data), &data);

	data |= 0x2;

	vnt_control_out(priv, MESSAGE_TYPE_WRITE, USB_REG4,
		MESSAGE_REQUEST_MEM, sizeof(data), &data);

	return true;
}

/*
 * Description: Set ShortSlotTime mode
 *
 * Parameters:
 *  In:
 *	priv	- Device Structure
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void BBvSetShortSlotTime(struct vnt_private *priv)
{
	u8 bb_vga = 0;

	if (priv->bShortSlotTime)
		priv->byBBRxConf &= 0xdf;
	else
		priv->byBBRxConf |= 0x20;

	vnt_control_in_u8(priv, MESSAGE_REQUEST_BBREG, 0xe7, &bb_vga);

	if (bb_vga == priv->abyBBVGA[0])
		priv->byBBRxConf |= 0x20;

	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0a, priv->byBBRxConf);
}

void BBvSetVGAGainOffset(struct vnt_private *priv, u8 data)
{

	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0xE7, data);

	/* patch for 3253B0 Baseband with Cardbus module */
	if (priv->bShortSlotTime)
		priv->byBBRxConf &= 0xdf; /* 1101 1111 */
	else
		priv->byBBRxConf |= 0x20; /* 0010 0000 */

	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0a, priv->byBBRxConf);
}

/*
 * Description: BBvSetDeepSleep
 *
 * Parameters:
 *  In:
 *	priv	- Device Structure
 *  Out:
 *      none
 *
 * Return Value: none
 *
 */
void BBvSetDeepSleep(struct vnt_private *priv)
{
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0c, 0x17);/* CR12 */
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0d, 0xB9);/* CR13 */
}

void BBvExitDeepSleep(struct vnt_private *priv)
{
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0c, 0x00);/* CR12 */
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0x0d, 0x01);/* CR13 */
}

void BBvUpdatePreEDThreshold(struct vnt_private *priv, int scanning)
{
	u8 cr_201 = 0x0, cr_206 = 0x0;
	u8 ed_inx = priv->byBBPreEDIndex;

	switch (priv->byRFType) {
	case RF_AL2230:
	case RF_AL2230S:
	case RF_AIROHA7230:
		if (scanning) { /* Max sensitivity */
			ed_inx = 0;
			cr_206 = 0x30;
			break;
		}

		if (priv->byBBPreEDRSSI <= 45) {
			ed_inx = 20;
			cr_201 = 0xff;
		} else if (priv->byBBPreEDRSSI <= 46) {
			ed_inx = 19;
			cr_201 = 0x1a;
		} else if (priv->byBBPreEDRSSI <= 47) {
			ed_inx = 18;
			cr_201 = 0x15;
		} else if (priv->byBBPreEDRSSI <= 49) {
			ed_inx = 17;
			cr_201 = 0xe;
		} else if (priv->byBBPreEDRSSI <= 51) {
			ed_inx = 16;
			cr_201 = 0x9;
		} else if (priv->byBBPreEDRSSI <= 53) {
			ed_inx = 15;
			cr_201 = 0x6;
		} else if (priv->byBBPreEDRSSI <= 55) {
			ed_inx = 14;
			cr_201 = 0x3;
		} else if (priv->byBBPreEDRSSI <= 56) {
			ed_inx = 13;
			cr_201 = 0x2;
			cr_206 = 0xa0;
		} else if (priv->byBBPreEDRSSI <= 57) {
			ed_inx = 12;
			cr_201 = 0x2;
			cr_206 = 0x20;
		} else if (priv->byBBPreEDRSSI <= 58) {
			ed_inx = 11;
			cr_201 = 0x1;
			cr_206 = 0xa0;
		} else if (priv->byBBPreEDRSSI <= 59) {
			ed_inx = 10;
			cr_201 = 0x1;
			cr_206 = 0x54;
		} else if (priv->byBBPreEDRSSI <= 60) {
			ed_inx = 9;
			cr_201 = 0x1;
			cr_206 = 0x18;
		} else if (priv->byBBPreEDRSSI <= 61) {
			ed_inx = 8;
			cr_206 = 0xe3;
		} else if (priv->byBBPreEDRSSI <= 62) {
			ed_inx = 7;
			cr_206 = 0xb9;
		} else if (priv->byBBPreEDRSSI <= 63) {
			ed_inx = 6;
			cr_206 = 0x93;
		} else if (priv->byBBPreEDRSSI <= 64) {
			ed_inx = 5;
			cr_206 = 0x79;
		} else if (priv->byBBPreEDRSSI <= 65) {
			ed_inx = 4;
			cr_206 = 0x62;
		} else if (priv->byBBPreEDRSSI <= 66) {
			ed_inx = 3;
			cr_206 = 0x51;
		} else if (priv->byBBPreEDRSSI <= 67) {
			ed_inx = 2;
			cr_206 = 0x43;
		} else if (priv->byBBPreEDRSSI <= 68) {
			ed_inx = 1;
			cr_206 = 0x36;
		} else {
			ed_inx = 0;
			cr_206 = 0x30;
		}
		break;

	case RF_VT3226:
	case RF_VT3226D0:
		if (scanning)	{ /* Max sensitivity */
			ed_inx = 0;
			cr_206 = 0x24;
			break;
		}

		if (priv->byBBPreEDRSSI <= 41) {
			ed_inx = 22;
			cr_201 = 0xff;
		} else if (priv->byBBPreEDRSSI <= 42) {
			ed_inx = 21;
			cr_201 = 0x36;
		} else if (priv->byBBPreEDRSSI <= 43) {
			ed_inx = 20;
			cr_201 = 0x26;
		} else if (priv->byBBPreEDRSSI <= 45) {
			ed_inx = 19;
			cr_201 = 0x18;
		} else if (priv->byBBPreEDRSSI <= 47) {
			ed_inx = 18;
			cr_201 = 0x11;
		} else if (priv->byBBPreEDRSSI <= 49) {
			ed_inx = 17;
			cr_201 = 0xa;
		} else if (priv->byBBPreEDRSSI <= 51) {
			ed_inx = 16;
			cr_201 = 0x7;
		} else if (priv->byBBPreEDRSSI <= 53) {
			ed_inx = 15;
			cr_201 = 0x4;
		} else if (priv->byBBPreEDRSSI <= 55) {
			ed_inx = 14;
			cr_201 = 0x2;
			cr_206 = 0xc0;
		} else if (priv->byBBPreEDRSSI <= 56) {
			ed_inx = 13;
			cr_201 = 0x2;
			cr_206 = 0x30;
		} else if (priv->byBBPreEDRSSI <= 57) {
			ed_inx = 12;
			cr_201 = 0x1;
			cr_206 = 0xb0;
		} else if (priv->byBBPreEDRSSI <= 58) {
			ed_inx = 11;
			cr_201 = 0x1;
			cr_206 = 0x70;
		} else if (priv->byBBPreEDRSSI <= 59) {
			ed_inx = 10;
			cr_201 = 0x1;
			cr_206 = 0x30;
		} else if (priv->byBBPreEDRSSI <= 60) {
			ed_inx = 9;
			cr_206 = 0xea;
		} else if (priv->byBBPreEDRSSI <= 61) {
			ed_inx = 8;
			cr_206 = 0xc0;
		} else if (priv->byBBPreEDRSSI <= 62) {
			ed_inx = 7;
			cr_206 = 0x9c;
		} else if (priv->byBBPreEDRSSI <= 63) {
			ed_inx = 6;
			cr_206 = 0x80;
		} else if (priv->byBBPreEDRSSI <= 64) {
			ed_inx = 5;
			cr_206 = 0x68;
		} else if (priv->byBBPreEDRSSI <= 65) {
			ed_inx = 4;
			cr_206 = 0x52;
		} else if (priv->byBBPreEDRSSI <= 66) {
			ed_inx = 3;
			cr_206 = 0x43;
		} else if (priv->byBBPreEDRSSI <= 67) {
			ed_inx = 2;
			cr_206 = 0x36;
		} else if (priv->byBBPreEDRSSI <= 68) {
			ed_inx = 1;
			cr_206 = 0x2d;
		} else {
			ed_inx = 0;
			cr_206 = 0x24;
		}
		break;

	case RF_VT3342A0:
		if (scanning) { /* need Max sensitivity */
			ed_inx = 0;
			cr_206 = 0x38;
			break;
		}

		if (priv->byBBPreEDRSSI <= 41) {
			ed_inx = 20;
			cr_201 = 0xff;
		} else if (priv->byBBPreEDRSSI <= 42) {
			ed_inx = 19;
			cr_201 = 0x36;
		} else if (priv->byBBPreEDRSSI <= 43) {
			ed_inx = 18;
			cr_201 = 0x26;
		} else if (priv->byBBPreEDRSSI <= 45) {
			ed_inx = 17;
			cr_201 = 0x18;
		} else if (priv->byBBPreEDRSSI <= 47) {
			ed_inx = 16;
			cr_201 = 0x11;
		} else if (priv->byBBPreEDRSSI <= 49) {
			ed_inx = 15;
			cr_201 = 0xa;
		} else if (priv->byBBPreEDRSSI <= 51) {
			ed_inx = 14;
			cr_201 = 0x7;
		} else if (priv->byBBPreEDRSSI <= 53) {
			ed_inx = 13;
			cr_201 = 0x4;
		} else if (priv->byBBPreEDRSSI <= 55) {
			ed_inx = 12;
			cr_201 = 0x2;
			cr_206 = 0xc0;
		} else if (priv->byBBPreEDRSSI <= 56) {
			ed_inx = 11;
			cr_201 = 0x2;
			cr_206 = 0x30;
		} else if (priv->byBBPreEDRSSI <= 57) {
			ed_inx = 10;
			cr_201 = 0x1;
			cr_206 = 0xb0;
		} else if (priv->byBBPreEDRSSI <= 58) {
			ed_inx = 9;
			cr_201 = 0x1;
			cr_206 = 0x70;
		} else if (priv->byBBPreEDRSSI <= 59) {
			ed_inx = 8;
			cr_201 = 0x1;
			cr_206 = 0x30;
		} else if (priv->byBBPreEDRSSI <= 60) {
			ed_inx = 7;
			cr_206 = 0xea;
		} else if (priv->byBBPreEDRSSI <= 61) {
			ed_inx = 6;
			cr_206 = 0xc0;
		} else if (priv->byBBPreEDRSSI <= 62) {
			ed_inx = 5;
			cr_206 = 0x9c;
		} else if (priv->byBBPreEDRSSI <= 63) {
			ed_inx = 4;
			cr_206 = 0x80;
		} else if (priv->byBBPreEDRSSI <= 64) {
			ed_inx = 3;
			cr_206 = 0x68;
		} else if (priv->byBBPreEDRSSI <= 65) {
			ed_inx = 2;
			cr_206 = 0x52;
		} else if (priv->byBBPreEDRSSI <= 66) {
			ed_inx = 1;
			cr_206 = 0x43;
		} else {
			ed_inx = 0;
			cr_206 = 0x38;
		}
		break;

	}

	if (ed_inx == priv->byBBPreEDIndex && !scanning)
		return;

	priv->byBBPreEDIndex = ed_inx;

	dev_dbg(&priv->usb->dev, "%s byBBPreEDRSSI %d\n",
					__func__, priv->byBBPreEDRSSI);

	if (!cr_201 && !cr_206)
		return;

	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0xc9, cr_201);
	vnt_control_out_u8(priv, MESSAGE_REQUEST_BBREG, 0xce, cr_206);
}

