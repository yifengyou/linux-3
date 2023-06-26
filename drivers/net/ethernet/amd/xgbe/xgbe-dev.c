/*
 * AMD 10Gb Ethernet driver
 *
 * This file is available to you under your choice of the following two
 * licenses:
 *
 * License 1: GPLv2
 *
 * Copyright (c) 2014 Advanced Micro Devices, Inc.
 *
 * This file is free software; you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or (at
 * your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *     The Synopsys DWC ETHER XGMAC Software Driver and documentation
 *     (hereinafter "Software") is an unsupported proprietary work of Synopsys,
 *     Inc. unless otherwise expressly agreed to in writing between Synopsys
 *     and you.
 *
 *     The Software IS NOT an item of Licensed Software or Licensed Product
 *     under any End User Software License Agreement or Agreement for Licensed
 *     Product with Synopsys or any supplement thereto.  Permission is hereby
 *     granted, free of charge, to any person obtaining a copy of this software
 *     annotated with this license and the Software, to deal in the Software
 *     without restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *     of the Software, and to permit persons to whom the Software is furnished
 *     to do so, subject to the following conditions:
 *
 *     The above copyright notice and this permission notice shall be included
 *     in all copies or substantial portions of the Software.
 *
 *     THIS SOFTWARE IS BEING DISTRIBUTED BY SYNOPSYS SOLELY ON AN "AS IS"
 *     BASIS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *     TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *     PARTICULAR PURPOSE ARE HEREBY DISCLAIMED. IN NO EVENT SHALL SYNOPSYS
 *     BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *     CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *     SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *     INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *     ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 *     THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * License 2: Modified BSD
 *
 * Copyright (c) 2014 Advanced Micro Devices, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Advanced Micro Devices, Inc. nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *     The Synopsys DWC ETHER XGMAC Software Driver and documentation
 *     (hereinafter "Software") is an unsupported proprietary work of Synopsys,
 *     Inc. unless otherwise expressly agreed to in writing between Synopsys
 *     and you.
 *
 *     The Software IS NOT an item of Licensed Software or Licensed Product
 *     under any End User Software License Agreement or Agreement for Licensed
 *     Product with Synopsys or any supplement thereto.  Permission is hereby
 *     granted, free of charge, to any person obtaining a copy of this software
 *     annotated with this license and the Software, to deal in the Software
 *     without restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 *     of the Software, and to permit persons to whom the Software is furnished
 *     to do so, subject to the following conditions:
 *
 *     The above copyright notice and this permission notice shall be included
 *     in all copies or substantial portions of the Software.
 *
 *     THIS SOFTWARE IS BEING DISTRIBUTED BY SYNOPSYS SOLELY ON AN "AS IS"
 *     BASIS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *     TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *     PARTICULAR PURPOSE ARE HEREBY DISCLAIMED. IN NO EVENT SHALL SYNOPSYS
 *     BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *     CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *     SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *     INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *     ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 *     THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/phy.h>
#include <linux/clk.h>

#include "xgbe.h"
#include "xgbe-common.h"


static unsigned int xgbe_usec_to_riwt(struct xgbe_prv_data *pdata,
				      unsigned int usec)
{
	unsigned long rate;
	unsigned int ret;

	DBGPR("-->xgbe_usec_to_riwt\n");

	rate = clk_get_rate(pdata->sysclock);

	/*
	 * Convert the input usec value to the watchdog timer value. Each
	 * watchdog timer value is equivalent to 256 clock cycles.
	 * Calculate the required value as:
	 *   ( usec * ( system_clock_mhz / 10^6 ) / 256
	 */
	ret = (usec * (rate / 1000000)) / 256;

	DBGPR("<--xgbe_usec_to_riwt\n");

	return ret;
}

static unsigned int xgbe_riwt_to_usec(struct xgbe_prv_data *pdata,
				      unsigned int riwt)
{
	unsigned long rate;
	unsigned int ret;

	DBGPR("-->xgbe_riwt_to_usec\n");

	rate = clk_get_rate(pdata->sysclock);

	/*
	 * Convert the input watchdog timer value to the usec value. Each
	 * watchdog timer value is equivalent to 256 clock cycles.
	 * Calculate the required value as:
	 *   ( riwt * 256 ) / ( system_clock_mhz / 10^6 )
	 */
	ret = (riwt * 256) / (rate / 1000000);

	DBGPR("<--xgbe_riwt_to_usec\n");

	return ret;
}

static int xgbe_config_pblx8(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++)
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_CR, PBLX8,
				       pdata->pblx8);

	return 0;
}

static int xgbe_get_tx_pbl_val(struct xgbe_prv_data *pdata)
{
	return XGMAC_DMA_IOREAD_BITS(pdata->channel, DMA_CH_TCR, PBL);
}

static int xgbe_config_tx_pbl_val(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, PBL,
				       pdata->tx_pbl);
	}

	return 0;
}

static int xgbe_get_rx_pbl_val(struct xgbe_prv_data *pdata)
{
	return XGMAC_DMA_IOREAD_BITS(pdata->channel, DMA_CH_RCR, PBL);
}

static int xgbe_config_rx_pbl_val(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, PBL,
				       pdata->rx_pbl);
	}

	return 0;
}

static int xgbe_config_osp_mode(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, OSP,
				       pdata->tx_osp_mode);
	}

	return 0;
}

static int xgbe_config_rsf_mode(struct xgbe_prv_data *pdata, unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RSF, val);

	return 0;
}

static int xgbe_config_tsf_mode(struct xgbe_prv_data *pdata, unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TSF, val);

	return 0;
}

static int xgbe_config_rx_threshold(struct xgbe_prv_data *pdata,
				    unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RTC, val);

	return 0;
}

static int xgbe_config_tx_threshold(struct xgbe_prv_data *pdata,
				    unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TTC, val);

	return 0;
}

static int xgbe_config_rx_coalesce(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RIWT, RWT,
				       pdata->rx_riwt);
	}

	return 0;
}

static int xgbe_config_tx_coalesce(struct xgbe_prv_data *pdata)
{
	return 0;
}

static void xgbe_config_rx_buffer_size(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, RBSZ,
				       pdata->rx_buf_size);
	}
}

static void xgbe_config_tso_mode(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, TSE, 1);
	}
}

static int xgbe_disable_tx_flow_control(struct xgbe_prv_data *pdata)
{
	unsigned int max_q_count, q_count;
	unsigned int reg, reg_val;
	unsigned int i;

	/* Clear MTL flow control */
	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, EHFC, 0);

	/* Clear MAC flow control */
	max_q_count = XGMAC_MAX_FLOW_CONTROL_QUEUES;
	q_count = min_t(unsigned int, pdata->hw_feat.rx_q_cnt, max_q_count);
	reg = MAC_Q0TFCR;
	for (i = 0; i < q_count; i++) {
		reg_val = XGMAC_IOREAD(pdata, reg);
		XGMAC_SET_BITS(reg_val, MAC_Q0TFCR, TFE, 0);
		XGMAC_IOWRITE(pdata, reg, reg_val);

		reg += MAC_QTFCR_INC;
	}

	return 0;
}

static int xgbe_enable_tx_flow_control(struct xgbe_prv_data *pdata)
{
	unsigned int max_q_count, q_count;
	unsigned int reg, reg_val;
	unsigned int i;

	/* Set MTL flow control */
	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, EHFC, 1);

	/* Set MAC flow control */
	max_q_count = XGMAC_MAX_FLOW_CONTROL_QUEUES;
	q_count = min_t(unsigned int, pdata->hw_feat.rx_q_cnt, max_q_count);
	reg = MAC_Q0TFCR;
	for (i = 0; i < q_count; i++) {
		reg_val = XGMAC_IOREAD(pdata, reg);

		/* Enable transmit flow control */
		XGMAC_SET_BITS(reg_val, MAC_Q0TFCR, TFE, 1);
		/* Set pause time */
		XGMAC_SET_BITS(reg_val, MAC_Q0TFCR, PT, 0xffff);

		XGMAC_IOWRITE(pdata, reg, reg_val);

		reg += MAC_QTFCR_INC;
	}

	return 0;
}

static int xgbe_disable_rx_flow_control(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_RFCR, RFE, 0);

	return 0;
}

static int xgbe_enable_rx_flow_control(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_RFCR, RFE, 1);

	return 0;
}

static int xgbe_config_tx_flow_control(struct xgbe_prv_data *pdata)
{
	if (pdata->tx_pause)
		xgbe_enable_tx_flow_control(pdata);
	else
		xgbe_disable_tx_flow_control(pdata);

	return 0;
}

static int xgbe_config_rx_flow_control(struct xgbe_prv_data *pdata)
{
	if (pdata->rx_pause)
		xgbe_enable_rx_flow_control(pdata);
	else
		xgbe_disable_rx_flow_control(pdata);

	return 0;
}

static void xgbe_config_flow_control(struct xgbe_prv_data *pdata)
{
	xgbe_config_tx_flow_control(pdata);
	xgbe_config_rx_flow_control(pdata);
}

static void xgbe_enable_dma_interrupts(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int dma_ch_isr, dma_ch_ier;
	unsigned int i;

	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		/* Clear all the interrupts which are set */
		dma_ch_isr = XGMAC_DMA_IOREAD(channel, DMA_CH_SR);
		XGMAC_DMA_IOWRITE(channel, DMA_CH_SR, dma_ch_isr);

		/* Clear all interrupt enable bits */
		dma_ch_ier = 0;

		/* Enable following interrupts
		 *   NIE  - Normal Interrupt Summary Enable
		 *   AIE  - Abnormal Interrupt Summary Enable
		 *   FBEE - Fatal Bus Error Enable
		 */
		XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, NIE, 1);
		XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, AIE, 1);
		XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, FBEE, 1);

		if (channel->tx_ring) {
			/* Enable the following Tx interrupts
			 *   TIE  - Transmit Interrupt Enable (unless polling)
			 */
			XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, TIE, 1);
		}
		if (channel->rx_ring) {
			/* Enable following Rx interrupts
			 *   RBUE - Receive Buffer Unavailable Enable
			 *   RIE  - Receive Interrupt Enable
			 */
			XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, RBUE, 1);
			XGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, RIE, 1);
		}

		XGMAC_DMA_IOWRITE(channel, DMA_CH_IER, dma_ch_ier);
	}
}

static void xgbe_enable_mtl_interrupts(struct xgbe_prv_data *pdata)
{
	unsigned int mtl_q_isr;
	unsigned int q_count, i;

	q_count = max(pdata->hw_feat.tx_q_cnt, pdata->hw_feat.rx_q_cnt);
	for (i = 0; i < q_count; i++) {
		/* Clear all the interrupts which are set */
		mtl_q_isr = XGMAC_MTL_IOREAD(pdata, i, MTL_Q_ISR);
		XGMAC_MTL_IOWRITE(pdata, i, MTL_Q_ISR, mtl_q_isr);

		/* No MTL interrupts to be enabled */
		XGMAC_MTL_IOWRITE(pdata, i, MTL_Q_ISR, 0);
	}
}

static void xgbe_enable_mac_interrupts(struct xgbe_prv_data *pdata)
{
	/* No MAC interrupts to be enabled */
	XGMAC_IOWRITE(pdata, MAC_IER, 0);

	/* Enable all counter interrupts */
	XGMAC_IOWRITE_BITS(pdata, MMC_RIER, ALL_INTERRUPTS, 0xff);
	XGMAC_IOWRITE_BITS(pdata, MMC_TIER, ALL_INTERRUPTS, 0xff);
}

static int xgbe_set_gmii_speed(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, SS, 0x3);

	return 0;
}

static int xgbe_set_gmii_2500_speed(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, SS, 0x2);

	return 0;
}

static int xgbe_set_xgmii_speed(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, SS, 0);

	return 0;
}

static int xgbe_set_promiscuous_mode(struct xgbe_prv_data *pdata,
				     unsigned int enable)
{
	unsigned int val = enable ? 1 : 0;

	if (XGMAC_IOREAD_BITS(pdata, MAC_PFR, PR) == val)
		return 0;

	DBGPR("  %s promiscuous mode\n", enable ? "entering" : "leaving");
	XGMAC_IOWRITE_BITS(pdata, MAC_PFR, PR, val);

	return 0;
}

static int xgbe_set_all_multicast_mode(struct xgbe_prv_data *pdata,
				       unsigned int enable)
{
	unsigned int val = enable ? 1 : 0;

	if (XGMAC_IOREAD_BITS(pdata, MAC_PFR, PM) == val)
		return 0;

	DBGPR("  %s allmulti mode\n", enable ? "entering" : "leaving");
	XGMAC_IOWRITE_BITS(pdata, MAC_PFR, PM, val);

	return 0;
}

static int xgbe_set_addn_mac_addrs(struct xgbe_prv_data *pdata,
				   unsigned int am_mode)
{
	struct netdev_hw_addr *ha;
	unsigned int mac_reg;
	unsigned int mac_addr_hi, mac_addr_lo;
	u8 *mac_addr;
	unsigned int i;

	XGMAC_IOWRITE_BITS(pdata, MAC_PFR, HUC, 0);
	XGMAC_IOWRITE_BITS(pdata, MAC_PFR, HMC, 0);

	i = 0;
	mac_reg = MAC_MACA1HR;

	netdev_for_each_uc_addr(ha, pdata->netdev) {
		mac_addr_lo = 0;
		mac_addr_hi = 0;
		mac_addr = (u8 *)&mac_addr_lo;
		mac_addr[0] = ha->addr[0];
		mac_addr[1] = ha->addr[1];
		mac_addr[2] = ha->addr[2];
		mac_addr[3] = ha->addr[3];
		mac_addr = (u8 *)&mac_addr_hi;
		mac_addr[0] = ha->addr[4];
		mac_addr[1] = ha->addr[5];

		DBGPR("  adding unicast address %pM at 0x%04x\n",
		      ha->addr, mac_reg);

		XGMAC_SET_BITS(mac_addr_hi, MAC_MACA1HR, AE, 1);

		XGMAC_IOWRITE(pdata, mac_reg, mac_addr_hi);
		mac_reg += MAC_MACA_INC;
		XGMAC_IOWRITE(pdata, mac_reg, mac_addr_lo);
		mac_reg += MAC_MACA_INC;

		i++;
	}

	if (!am_mode) {
		netdev_for_each_mc_addr(ha, pdata->netdev) {
			mac_addr_lo = 0;
			mac_addr_hi = 0;
			mac_addr = (u8 *)&mac_addr_lo;
			mac_addr[0] = ha->addr[0];
			mac_addr[1] = ha->addr[1];
			mac_addr[2] = ha->addr[2];
			mac_addr[3] = ha->addr[3];
			mac_addr = (u8 *)&mac_addr_hi;
			mac_addr[0] = ha->addr[4];
			mac_addr[1] = ha->addr[5];

			DBGPR("  adding multicast address %pM at 0x%04x\n",
			      ha->addr, mac_reg);

			XGMAC_SET_BITS(mac_addr_hi, MAC_MACA1HR, AE, 1);

			XGMAC_IOWRITE(pdata, mac_reg, mac_addr_hi);
			mac_reg += MAC_MACA_INC;
			XGMAC_IOWRITE(pdata, mac_reg, mac_addr_lo);
			mac_reg += MAC_MACA_INC;

			i++;
		}
	}

	/* Clear remaining additional MAC address entries */
	for (; i < pdata->hw_feat.addn_mac; i++) {
		XGMAC_IOWRITE(pdata, mac_reg, 0);
		mac_reg += MAC_MACA_INC;
		XGMAC_IOWRITE(pdata, mac_reg, 0);
		mac_reg += MAC_MACA_INC;
	}

	return 0;
}

static int xgbe_set_mac_address(struct xgbe_prv_data *pdata, u8 *addr)
{
	unsigned int mac_addr_hi, mac_addr_lo;

	mac_addr_hi = (addr[5] <<  8) | (addr[4] <<  0);
	mac_addr_lo = (addr[3] << 24) | (addr[2] << 16) |
		      (addr[1] <<  8) | (addr[0] <<  0);

	XGMAC_IOWRITE(pdata, MAC_MACA0HR, mac_addr_hi);
	XGMAC_IOWRITE(pdata, MAC_MACA0LR, mac_addr_lo);

	return 0;
}

static int xgbe_read_mmd_regs(struct xgbe_prv_data *pdata, int prtad,
			      int mmd_reg)
{
	unsigned int mmd_address;
	int mmd_data;

	if (mmd_reg & MII_ADDR_C45)
		mmd_address = mmd_reg & ~MII_ADDR_C45;
	else
		mmd_address = (pdata->mdio_mmd << 16) | (mmd_reg & 0xffff);

	/* The PCS registers are accessed using mmio. The underlying APB3
	 * management interface uses indirect addressing to access the MMD
	 * register sets. This requires accessing of the PCS register in two
	 * phases, an address phase and a data phase.
	 *
	 * The mmio interface is based on 32-bit offsets and values. All
	 * register offsets must therefore be adjusted by left shifting the
	 * offset 2 bits and reading 32 bits of data.
	 */
	mutex_lock(&pdata->xpcs_mutex);
	XPCS_IOWRITE(pdata, PCS_MMD_SELECT << 2, mmd_address >> 8);
	mmd_data = XPCS_IOREAD(pdata, (mmd_address & 0xff) << 2);
	mutex_unlock(&pdata->xpcs_mutex);

	return mmd_data;
}

static void xgbe_write_mmd_regs(struct xgbe_prv_data *pdata, int prtad,
				int mmd_reg, int mmd_data)
{
	unsigned int mmd_address;

	if (mmd_reg & MII_ADDR_C45)
		mmd_address = mmd_reg & ~MII_ADDR_C45;
	else
		mmd_address = (pdata->mdio_mmd << 16) | (mmd_reg & 0xffff);

	/* The PCS registers are accessed using mmio. The underlying APB3
	 * management interface uses indirect addressing to access the MMD
	 * register sets. This requires accessing of the PCS register in two
	 * phases, an address phase and a data phase.
	 *
	 * The mmio interface is based on 32-bit offsets and values. All
	 * register offsets must therefore be adjusted by left shifting the
	 * offset 2 bits and reading 32 bits of data.
	 */
	mutex_lock(&pdata->xpcs_mutex);
	XPCS_IOWRITE(pdata, PCS_MMD_SELECT << 2, mmd_address >> 8);
	XPCS_IOWRITE(pdata, (mmd_address & 0xff) << 2, mmd_data);
	mutex_unlock(&pdata->xpcs_mutex);
}

static int xgbe_tx_complete(struct xgbe_ring_desc *rdesc)
{
	return !XGMAC_GET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, OWN);
}

static int xgbe_disable_rx_csum(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, IPC, 0);

	return 0;
}

static int xgbe_enable_rx_csum(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, IPC, 1);

	return 0;
}

static int xgbe_enable_rx_vlan_stripping(struct xgbe_prv_data *pdata)
{
	/* Put the VLAN tag in the Rx descriptor */
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLRXS, 1);

	/* Don't check the VLAN type */
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, DOVLTC, 1);

	/* Check only C-TAG (0x8100) packets */
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, ERSVLM, 0);

	/* Don't consider an S-TAG (0x88A8) packet as a VLAN packet */
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, ESVL, 0);

	/* Enable VLAN tag stripping */
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLS, 0x3);

	return 0;
}

static int xgbe_disable_rx_vlan_stripping(struct xgbe_prv_data *pdata)
{
	XGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLS, 0);

	return 0;
}

static void xgbe_tx_desc_reset(struct xgbe_ring_data *rdata)
{
	struct xgbe_ring_desc *rdesc = rdata->rdesc;

	/* Reset the Tx descriptor
	 *   Set buffer 1 (lo) address to zero
	 *   Set buffer 1 (hi) address to zero
	 *   Reset all other control bits (IC, TTSE, B2L & B1L)
	 *   Reset all other control bits (OWN, CTXT, FD, LD, CPC, CIC, etc)
	 */
	rdesc->desc0 = 0;
	rdesc->desc1 = 0;
	rdesc->desc2 = 0;
	rdesc->desc3 = 0;
}

static void xgbe_tx_desc_init(struct xgbe_channel *channel)
{
	struct xgbe_ring *ring = channel->tx_ring;
	struct xgbe_ring_data *rdata;
	struct xgbe_ring_desc *rdesc;
	int i;
	int start_index = ring->cur;

	DBGPR("-->tx_desc_init\n");

	/* Initialze all descriptors */
	for (i = 0; i < ring->rdesc_count; i++) {
		rdata = GET_DESC_DATA(ring, i);
		rdesc = rdata->rdesc;

		/* Initialize Tx descriptor
		 *   Set buffer 1 (lo) address to zero
		 *   Set buffer 1 (hi) address to zero
		 *   Reset all other control bits (IC, TTSE, B2L & B1L)
		 *   Reset all other control bits (OWN, CTXT, FD, LD, CPC, CIC,
		 *     etc)
		 */
		rdesc->desc0 = 0;
		rdesc->desc1 = 0;
		rdesc->desc2 = 0;
		rdesc->desc3 = 0;
	}

	/* Make sure everything is written to the descriptor(s) before
	 * telling the device about them
	 */
	wmb();

	/* Update the total number of Tx descriptors */
	XGMAC_DMA_IOWRITE(channel, DMA_CH_TDRLR, ring->rdesc_count - 1);

	/* Update the starting address of descriptor ring */
	rdata = GET_DESC_DATA(ring, start_index);
	XGMAC_DMA_IOWRITE(channel, DMA_CH_TDLR_HI,
			  upper_32_bits(rdata->rdesc_dma));
	XGMAC_DMA_IOWRITE(channel, DMA_CH_TDLR_LO,
			  lower_32_bits(rdata->rdesc_dma));

	DBGPR("<--tx_desc_init\n");
}

static void xgbe_rx_desc_reset(struct xgbe_ring_data *rdata)
{
	struct xgbe_ring_desc *rdesc = rdata->rdesc;

	/* Reset the Rx descriptor
	 *   Set buffer 1 (lo) address to dma address (lo)
	 *   Set buffer 1 (hi) address to dma address (hi)
	 *   Set buffer 2 (lo) address to zero
	 *   Set buffer 2 (hi) address to zero and set control bits
	 *     OWN and INTE
	 */
	rdesc->desc0 = cpu_to_le32(lower_32_bits(rdata->skb_dma));
	rdesc->desc1 = cpu_to_le32(upper_32_bits(rdata->skb_dma));
	rdesc->desc2 = 0;

	rdesc->desc3 = 0;
	if (rdata->interrupt)
		XGMAC_SET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, INTE, 1);

	/* Since the Rx DMA engine is likely running, make sure everything
	 * is written to the descriptor(s) before setting the OWN bit
	 * for the descriptor
	 */
	wmb();

	XGMAC_SET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, OWN, 1);

	/* Make sure ownership is written to the descriptor */
	wmb();
}

static void xgbe_rx_desc_init(struct xgbe_channel *channel)
{
	struct xgbe_prv_data *pdata = channel->pdata;
	struct xgbe_ring *ring = channel->rx_ring;
	struct xgbe_ring_data *rdata;
	struct xgbe_ring_desc *rdesc;
	unsigned int start_index = ring->cur;
	unsigned int rx_coalesce, rx_frames;
	unsigned int i;

	DBGPR("-->rx_desc_init\n");

	rx_coalesce = (pdata->rx_riwt || pdata->rx_frames) ? 1 : 0;
	rx_frames = pdata->rx_frames;

	/* Initialize all descriptors */
	for (i = 0; i < ring->rdesc_count; i++) {
		rdata = GET_DESC_DATA(ring, i);
		rdesc = rdata->rdesc;

		/* Initialize Rx descriptor
		 *   Set buffer 1 (lo) address to dma address (lo)
		 *   Set buffer 1 (hi) address to dma address (hi)
		 *   Set buffer 2 (lo) address to zero
		 *   Set buffer 2 (hi) address to zero and set control
		 *     bits OWN and INTE appropriateley
		 */
		rdesc->desc0 = cpu_to_le32(lower_32_bits(rdata->skb_dma));
		rdesc->desc1 = cpu_to_le32(upper_32_bits(rdata->skb_dma));
		rdesc->desc2 = 0;
		rdesc->desc3 = 0;
		XGMAC_SET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, OWN, 1);
		XGMAC_SET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, INTE, 1);
		rdata->interrupt = 1;
		if (rx_coalesce && (!rx_frames || ((i + 1) % rx_frames))) {
			/* Clear interrupt on completion bit */
			XGMAC_SET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, INTE,
					  0);
			rdata->interrupt = 0;
		}
	}

	/* Make sure everything is written to the descriptors before
	 * telling the device about them
	 */
	wmb();

	/* Update the total number of Rx descriptors */
	XGMAC_DMA_IOWRITE(channel, DMA_CH_RDRLR, ring->rdesc_count - 1);

	/* Update the starting address of descriptor ring */
	rdata = GET_DESC_DATA(ring, start_index);
	XGMAC_DMA_IOWRITE(channel, DMA_CH_RDLR_HI,
			  upper_32_bits(rdata->rdesc_dma));
	XGMAC_DMA_IOWRITE(channel, DMA_CH_RDLR_LO,
			  lower_32_bits(rdata->rdesc_dma));

	/* Update the Rx Descriptor Tail Pointer */
	rdata = GET_DESC_DATA(ring, start_index + ring->rdesc_count - 1);
	XGMAC_DMA_IOWRITE(channel, DMA_CH_RDTR_LO,
			  lower_32_bits(rdata->rdesc_dma));

	DBGPR("<--rx_desc_init\n");
}

static void xgbe_pre_xmit(struct xgbe_channel *channel)
{
	struct xgbe_prv_data *pdata = channel->pdata;
	struct xgbe_ring *ring = channel->tx_ring;
	struct xgbe_ring_data *rdata;
	struct xgbe_ring_desc *rdesc;
	struct xgbe_packet_data *packet = &ring->packet_data;
	unsigned int csum, tso, vlan;
	unsigned int tso_context, vlan_context;
	unsigned int tx_coalesce, tx_frames;
	int start_index = ring->cur;
	int i;

	DBGPR("-->xgbe_pre_xmit\n");

	csum = XGMAC_GET_BITS(packet->attributes, TX_PACKET_ATTRIBUTES,
			      CSUM_ENABLE);
	tso = XGMAC_GET_BITS(packet->attributes, TX_PACKET_ATTRIBUTES,
			     TSO_ENABLE);
	vlan = XGMAC_GET_BITS(packet->attributes, TX_PACKET_ATTRIBUTES,
			      VLAN_CTAG);

	if (tso && (packet->mss != ring->tx.cur_mss))
		tso_context = 1;
	else
		tso_context = 0;

	if (vlan && (packet->vlan_ctag != ring->tx.cur_vlan_ctag))
		vlan_context = 1;
	else
		vlan_context = 0;

	tx_coalesce = (pdata->tx_usecs || pdata->tx_frames) ? 1 : 0;
	tx_frames = pdata->tx_frames;
	if (tx_coalesce && !channel->tx_timer_active)
		ring->coalesce_count = 0;

	rdata = GET_DESC_DATA(ring, ring->cur);
	rdesc = rdata->rdesc;

	/* Create a context descriptor if this is a TSO packet */
	if (tso_context || vlan_context) {
		if (tso_context) {
			DBGPR("  TSO context descriptor, mss=%u\n",
			      packet->mss);

			/* Set the MSS size */
			XGMAC_SET_BITS_LE(rdesc->desc2, TX_CONTEXT_DESC2,
					  MSS, packet->mss);

			/* Mark it as a CONTEXT descriptor */
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_CONTEXT_DESC3,
					  CTXT, 1);

			/* Indicate this descriptor contains the MSS */
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_CONTEXT_DESC3,
					  TCMSSV, 1);

			ring->tx.cur_mss = packet->mss;
		}

		if (vlan_context) {
			DBGPR("  VLAN context descriptor, ctag=%u\n",
			      packet->vlan_ctag);

			/* Mark it as a CONTEXT descriptor */
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_CONTEXT_DESC3,
					  CTXT, 1);

			/* Set the VLAN tag */
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_CONTEXT_DESC3,
					  VT, packet->vlan_ctag);

			/* Indicate this descriptor contains the VLAN tag */
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_CONTEXT_DESC3,
					  VLTV, 1);

			ring->tx.cur_vlan_ctag = packet->vlan_ctag;
		}

		ring->cur++;
		rdata = GET_DESC_DATA(ring, ring->cur);
		rdesc = rdata->rdesc;
	}

	/* Update buffer address (for TSO this is the header) */
	rdesc->desc0 =  cpu_to_le32(lower_32_bits(rdata->skb_dma));
	rdesc->desc1 =  cpu_to_le32(upper_32_bits(rdata->skb_dma));

	/* Update the buffer length */
	XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, HL_B1L,
			  rdata->skb_dma_len);

	/* VLAN tag insertion check */
	if (vlan)
		XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, VTIR,
				  TX_NORMAL_DESC2_VLAN_INSERT);

	/* Set IC bit based on Tx coalescing settings */
	XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, IC, 1);
	if (tx_coalesce && (!tx_frames ||
			    (++ring->coalesce_count % tx_frames)))
		/* Clear IC bit */
		XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, IC, 0);

	/* Mark it as First Descriptor */
	XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, FD, 1);

	/* Mark it as a NORMAL descriptor */
	XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, CTXT, 0);

	/* Set OWN bit if not the first descriptor */
	if (ring->cur != start_index)
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, OWN, 1);

	if (tso) {
		/* Enable TSO */
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, TSE, 1);
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, TCPPL,
				  packet->tcp_payload_len);
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, TCPHDRLEN,
				  packet->tcp_header_len / 4);
	} else {
		/* Enable CRC and Pad Insertion */
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, CPC, 0);

		/* Enable HW CSUM */
		if (csum)
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3,
					  CIC, 0x3);

		/* Set the total length to be transmitted */
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, FL,
				  packet->length);
	}

	for (i = ring->cur - start_index + 1; i < packet->rdesc_count; i++) {
		ring->cur++;
		rdata = GET_DESC_DATA(ring, ring->cur);
		rdesc = rdata->rdesc;

		/* Update buffer address */
		rdesc->desc0 = cpu_to_le32(lower_32_bits(rdata->skb_dma));
		rdesc->desc1 = cpu_to_le32(upper_32_bits(rdata->skb_dma));

		/* Update the buffer length */
		XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, HL_B1L,
				  rdata->skb_dma_len);

		/* Set IC bit based on Tx coalescing settings */
		XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, IC, 1);
		if (tx_coalesce && (!tx_frames ||
				    (++ring->coalesce_count % tx_frames)))
			/* Clear IC bit */
			XGMAC_SET_BITS_LE(rdesc->desc2, TX_NORMAL_DESC2, IC, 0);

		/* Set OWN bit */
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, OWN, 1);

		/* Mark it as NORMAL descriptor */
		XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, CTXT, 0);

		/* Enable HW CSUM */
		if (csum)
			XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3,
					  CIC, 0x3);
	}

	/* Set LAST bit for the last descriptor */
	XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, LD, 1);

	/* In case the Tx DMA engine is running, make sure everything
	 * is written to the descriptor(s) before setting the OWN bit
	 * for the first descriptor
	 */
	wmb();

	/* Set OWN bit for the first descriptor */
	rdata = GET_DESC_DATA(ring, start_index);
	rdesc = rdata->rdesc;
	XGMAC_SET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, OWN, 1);

#ifdef XGMAC_ENABLE_TX_DESC_DUMP
	xgbe_dump_tx_desc(ring, start_index, packet->rdesc_count, 1);
#endif

	/* Make sure ownership is written to the descriptor */
	wmb();

	/* Issue a poll command to Tx DMA by writing address
	 * of next immediate free descriptor */
	ring->cur++;
	rdata = GET_DESC_DATA(ring, ring->cur);
	XGMAC_DMA_IOWRITE(channel, DMA_CH_TDTR_LO,
			  lower_32_bits(rdata->rdesc_dma));

	/* Start the Tx coalescing timer */
	if (tx_coalesce && !channel->tx_timer_active) {
		channel->tx_timer_active = 1;
		hrtimer_start(&channel->tx_timer,
			      ktime_set(0, pdata->tx_usecs * NSEC_PER_USEC),
			      HRTIMER_MODE_REL);
	}

	DBGPR("  %s: descriptors %u to %u written\n",
	      channel->name, start_index & (ring->rdesc_count - 1),
	      (ring->cur - 1) & (ring->rdesc_count - 1));

	DBGPR("<--xgbe_pre_xmit\n");
}

static int xgbe_dev_read(struct xgbe_channel *channel)
{
	struct xgbe_ring *ring = channel->rx_ring;
	struct xgbe_ring_data *rdata;
	struct xgbe_ring_desc *rdesc;
	struct xgbe_packet_data *packet = &ring->packet_data;
	unsigned int err, etlt;

	DBGPR("-->xgbe_dev_read: cur = %d\n", ring->cur);

	rdata = GET_DESC_DATA(ring, ring->cur);
	rdesc = rdata->rdesc;

	/* Check for data availability */
	if (XGMAC_GET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, OWN))
		return 1;

#ifdef XGMAC_ENABLE_RX_DESC_DUMP
	xgbe_dump_rx_desc(ring, rdesc, ring->cur);
#endif

	/* Get the packet length */
	rdata->len = XGMAC_GET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, PL);

	if (!XGMAC_GET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, LD)) {
		/* Not all the data has been transferred for this packet */
		XGMAC_SET_BITS(packet->attributes, RX_PACKET_ATTRIBUTES,
			       INCOMPLETE, 1);
		return 0;
	}

	/* This is the last of the data for this packet */
	XGMAC_SET_BITS(packet->attributes, RX_PACKET_ATTRIBUTES,
		       INCOMPLETE, 0);

	/* Set checksum done indicator as appropriate */
	if (channel->pdata->netdev->features & NETIF_F_RXCSUM)
		XGMAC_SET_BITS(packet->attributes, RX_PACKET_ATTRIBUTES,
			       CSUM_DONE, 1);

	/* Check for errors (only valid in last descriptor) */
	err = XGMAC_GET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, ES);
	etlt = XGMAC_GET_BITS_LE(rdesc->desc3, RX_NORMAL_DESC3, ETLT);
	DBGPR("  err=%u, etlt=%#x\n", err, etlt);

	if (!err || (err && !etlt)) {
		if (etlt == 0x09) {
			XGMAC_SET_BITS(packet->attributes, RX_PACKET_ATTRIBUTES,
				       VLAN_CTAG, 1);
			packet->vlan_ctag = XGMAC_GET_BITS_LE(rdesc->desc0,
							      RX_NORMAL_DESC0,
							      OVT);
			DBGPR("  vlan-ctag=0x%04x\n", packet->vlan_ctag);
		}
	} else {
		if ((etlt == 0x05) || (etlt == 0x06))
			XGMAC_SET_BITS(packet->attributes, RX_PACKET_ATTRIBUTES,
				       CSUM_DONE, 0);
		else
			XGMAC_SET_BITS(packet->errors, RX_PACKET_ERRORS,
				       FRAME, 1);
	}

	DBGPR("<--xgbe_dev_read: %s - descriptor=%u (cur=%d)\n", channel->name,
	      ring->cur & (ring->rdesc_count - 1), ring->cur);

	return 0;
}

static int xgbe_is_context_desc(struct xgbe_ring_desc *rdesc)
{
	/* Rx and Tx share CTXT bit, so check TDES3.CTXT bit */
	return XGMAC_GET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, CTXT);
}

static int xgbe_is_last_desc(struct xgbe_ring_desc *rdesc)
{
	/* Rx and Tx share LD bit, so check TDES3.LD bit */
	return XGMAC_GET_BITS_LE(rdesc->desc3, TX_NORMAL_DESC3, LD);
}

static void xgbe_save_interrupt_status(struct xgbe_channel *channel,
				       enum xgbe_int_state int_state)
{
	unsigned int dma_ch_ier;

	if (int_state == XGMAC_INT_STATE_SAVE) {
		channel->saved_ier = XGMAC_DMA_IOREAD(channel, DMA_CH_IER);
		channel->saved_ier &= DMA_INTERRUPT_MASK;
	} else {
		dma_ch_ier = XGMAC_DMA_IOREAD(channel, DMA_CH_IER);
		dma_ch_ier |= channel->saved_ier;
		XGMAC_DMA_IOWRITE(channel, DMA_CH_IER, dma_ch_ier);
	}
}

static int xgbe_enable_int(struct xgbe_channel *channel,
			   enum xgbe_int int_id)
{
	switch (int_id) {
	case XGMAC_INT_DMA_ISR_DC0IS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TIE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_TI:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TIE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_TPS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TXSE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_TBU:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TBUE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_RI:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RIE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_RBU:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RBUE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_RPS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RSE, 1);
		break;
	case XGMAC_INT_DMA_CH_SR_FBE:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, FBEE, 1);
		break;
	case XGMAC_INT_DMA_ALL:
		xgbe_save_interrupt_status(channel, XGMAC_INT_STATE_RESTORE);
		break;
	default:
		return -1;
	}

	return 0;
}

static int xgbe_disable_int(struct xgbe_channel *channel,
			    enum xgbe_int int_id)
{
	unsigned int dma_ch_ier;

	switch (int_id) {
	case XGMAC_INT_DMA_ISR_DC0IS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TIE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_TI:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TIE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_TPS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TXSE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_TBU:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, TBUE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_RI:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RIE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_RBU:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RBUE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_RPS:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, RSE, 0);
		break;
	case XGMAC_INT_DMA_CH_SR_FBE:
		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_IER, FBEE, 0);
		break;
	case XGMAC_INT_DMA_ALL:
		xgbe_save_interrupt_status(channel, XGMAC_INT_STATE_SAVE);

		dma_ch_ier = XGMAC_DMA_IOREAD(channel, DMA_CH_IER);
		dma_ch_ier &= ~DMA_INTERRUPT_MASK;
		XGMAC_DMA_IOWRITE(channel, DMA_CH_IER, dma_ch_ier);
		break;
	default:
		return -1;
	}

	return 0;
}

static int xgbe_exit(struct xgbe_prv_data *pdata)
{
	unsigned int count = 2000;

	DBGPR("-->xgbe_exit\n");

	/* Issue a software reset */
	XGMAC_IOWRITE_BITS(pdata, DMA_MR, SWR, 1);
	usleep_range(10, 15);

	/* Poll Until Poll Condition */
	while (--count && XGMAC_IOREAD_BITS(pdata, DMA_MR, SWR))
		usleep_range(500, 600);

	if (!count)
		return -EBUSY;

	DBGPR("<--xgbe_exit\n");

	return 0;
}

static int xgbe_flush_tx_queues(struct xgbe_prv_data *pdata)
{
	unsigned int i, count;

	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, FTQ, 1);

	/* Poll Until Poll Condition */
	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++) {
		count = 2000;
		while (--count && XGMAC_MTL_IOREAD_BITS(pdata, i,
							MTL_Q_TQOMR, FTQ))
			usleep_range(500, 600);

		if (!count)
			return -EBUSY;
	}

	return 0;
}

static void xgbe_config_dma_bus(struct xgbe_prv_data *pdata)
{
	/* Set enhanced addressing mode */
	XGMAC_IOWRITE_BITS(pdata, DMA_SBMR, EAME, 1);

	/* Set the System Bus mode */
	XGMAC_IOWRITE_BITS(pdata, DMA_SBMR, UNDEF, 1);
}

static void xgbe_config_dma_cache(struct xgbe_prv_data *pdata)
{
	unsigned int arcache, awcache;

	arcache = 0;
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, DRC, DMA_ARCACHE_SETTING);
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, DRD, DMA_ARDOMAIN_SETTING);
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, TEC, DMA_ARCACHE_SETTING);
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, TED, DMA_ARDOMAIN_SETTING);
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, THC, DMA_ARCACHE_SETTING);
	XGMAC_SET_BITS(arcache, DMA_AXIARCR, THD, DMA_ARDOMAIN_SETTING);
	XGMAC_IOWRITE(pdata, DMA_AXIARCR, arcache);

	awcache = 0;
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, DWC, DMA_AWCACHE_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, DWD, DMA_AWDOMAIN_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, RPC, DMA_AWCACHE_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, RPD, DMA_AWDOMAIN_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, RHC, DMA_AWCACHE_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, RHD, DMA_AWDOMAIN_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, TDC, DMA_AWCACHE_SETTING);
	XGMAC_SET_BITS(awcache, DMA_AXIAWCR, TDD, DMA_AWDOMAIN_SETTING);
	XGMAC_IOWRITE(pdata, DMA_AXIAWCR, awcache);
}

static void xgbe_config_mtl_mode(struct xgbe_prv_data *pdata)
{
	unsigned int i;

	/* Set Tx to weighted round robin scheduling algorithm (when
	 * traffic class is using ETS algorithm)
	 */
	XGMAC_IOWRITE_BITS(pdata, MTL_OMR, ETSALG, MTL_ETSALG_WRR);

	/* Set Tx traffic classes to strict priority algorithm */
	for (i = 0; i < XGBE_TC_CNT; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_TC_ETSCR, TSA, MTL_TSA_SP);

	/* Set Rx to strict priority algorithm */
	XGMAC_IOWRITE_BITS(pdata, MTL_OMR, RAA, MTL_RAA_SP);
}

static unsigned int xgbe_calculate_per_queue_fifo(unsigned long fifo_size,
						  unsigned char queue_count)
{
	unsigned int q_fifo_size = 0;
	enum xgbe_mtl_fifo_size p_fifo = XGMAC_MTL_FIFO_SIZE_256;

	/* Calculate Tx/Rx fifo share per queue */
	switch (fifo_size) {
	case 0:
		q_fifo_size = FIFO_SIZE_B(128);
		break;
	case 1:
		q_fifo_size = FIFO_SIZE_B(256);
		break;
	case 2:
		q_fifo_size = FIFO_SIZE_B(512);
		break;
	case 3:
		q_fifo_size = FIFO_SIZE_KB(1);
		break;
	case 4:
		q_fifo_size = FIFO_SIZE_KB(2);
		break;
	case 5:
		q_fifo_size = FIFO_SIZE_KB(4);
		break;
	case 6:
		q_fifo_size = FIFO_SIZE_KB(8);
		break;
	case 7:
		q_fifo_size = FIFO_SIZE_KB(16);
		break;
	case 8:
		q_fifo_size = FIFO_SIZE_KB(32);
		break;
	case 9:
		q_fifo_size = FIFO_SIZE_KB(64);
		break;
	case 10:
		q_fifo_size = FIFO_SIZE_KB(128);
		break;
	case 11:
		q_fifo_size = FIFO_SIZE_KB(256);
		break;
	}
	q_fifo_size = q_fifo_size / queue_count;

	/* Set the queue fifo size programmable value */
	if (q_fifo_size >= FIFO_SIZE_KB(256))
		p_fifo = XGMAC_MTL_FIFO_SIZE_256K;
	else if (q_fifo_size >= FIFO_SIZE_KB(128))
		p_fifo = XGMAC_MTL_FIFO_SIZE_128K;
	else if (q_fifo_size >= FIFO_SIZE_KB(64))
		p_fifo = XGMAC_MTL_FIFO_SIZE_64K;
	else if (q_fifo_size >= FIFO_SIZE_KB(32))
		p_fifo = XGMAC_MTL_FIFO_SIZE_32K;
	else if (q_fifo_size >= FIFO_SIZE_KB(16))
		p_fifo = XGMAC_MTL_FIFO_SIZE_16K;
	else if (q_fifo_size >= FIFO_SIZE_KB(8))
		p_fifo = XGMAC_MTL_FIFO_SIZE_8K;
	else if (q_fifo_size >= FIFO_SIZE_KB(4))
		p_fifo = XGMAC_MTL_FIFO_SIZE_4K;
	else if (q_fifo_size >= FIFO_SIZE_KB(2))
		p_fifo = XGMAC_MTL_FIFO_SIZE_2K;
	else if (q_fifo_size >= FIFO_SIZE_KB(1))
		p_fifo = XGMAC_MTL_FIFO_SIZE_1K;
	else if (q_fifo_size >= FIFO_SIZE_B(512))
		p_fifo = XGMAC_MTL_FIFO_SIZE_512;
	else if (q_fifo_size >= FIFO_SIZE_B(256))
		p_fifo = XGMAC_MTL_FIFO_SIZE_256;

	return p_fifo;
}

static void xgbe_config_tx_fifo_size(struct xgbe_prv_data *pdata)
{
	enum xgbe_mtl_fifo_size fifo_size;
	unsigned int i;

	fifo_size = xgbe_calculate_per_queue_fifo(pdata->hw_feat.tx_fifo_size,
						  pdata->hw_feat.tx_q_cnt);

	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TQS, fifo_size);

	netdev_notice(pdata->netdev, "%d Tx queues, %d byte fifo per queue\n",
		      pdata->hw_feat.tx_q_cnt, ((fifo_size + 1) * 256));
}

static void xgbe_config_rx_fifo_size(struct xgbe_prv_data *pdata)
{
	enum xgbe_mtl_fifo_size fifo_size;
	unsigned int i;

	fifo_size = xgbe_calculate_per_queue_fifo(pdata->hw_feat.rx_fifo_size,
						  pdata->hw_feat.rx_q_cnt);

	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RQS, fifo_size);

	netdev_notice(pdata->netdev, "%d Rx queues, %d byte fifo per queue\n",
		      pdata->hw_feat.rx_q_cnt, ((fifo_size + 1) * 256));
}

static void xgbe_config_rx_queue_mapping(struct xgbe_prv_data *pdata)
{
	unsigned int i, reg, reg_val;
	unsigned int q_count = pdata->hw_feat.rx_q_cnt;

	/* Select dynamic mapping of MTL Rx queue to DMA Rx channel */
	reg = MTL_RQDCM0R;
	reg_val = 0;
	for (i = 0; i < q_count;) {
		reg_val |= (0x80 << ((i++ % MTL_RQDCM_Q_PER_REG) << 3));

		if ((i % MTL_RQDCM_Q_PER_REG) && (i != q_count))
			continue;

		XGMAC_IOWRITE(pdata, reg, reg_val);

		reg += MTL_RQDCM_INC;
		reg_val = 0;
	}
}

static void xgbe_config_flow_control_threshold(struct xgbe_prv_data *pdata)
{
	unsigned int i;

	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++) {
		/* Activate flow control when less than 4k left in fifo */
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RFA, 2);

		/* De-activate flow control when more than 6k left in fifo */
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RFD, 4);
	}
}

static void xgbe_config_mac_address(struct xgbe_prv_data *pdata)
{
	xgbe_set_mac_address(pdata, pdata->netdev->dev_addr);
}

static void xgbe_config_jumbo_enable(struct xgbe_prv_data *pdata)
{
	unsigned int val;

	val = (pdata->netdev->mtu > XGMAC_STD_PACKET_MTU) ? 1 : 0;

	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, JE, val);
}

static void xgbe_config_checksum_offload(struct xgbe_prv_data *pdata)
{
	if (pdata->netdev->features & NETIF_F_RXCSUM)
		xgbe_enable_rx_csum(pdata);
	else
		xgbe_disable_rx_csum(pdata);
}

static void xgbe_config_vlan_support(struct xgbe_prv_data *pdata)
{
	if (pdata->netdev->features & NETIF_F_HW_VLAN_CTAG_RX)
		xgbe_enable_rx_vlan_stripping(pdata);
	else
		xgbe_disable_rx_vlan_stripping(pdata);
}

static void xgbe_tx_mmc_int(struct xgbe_prv_data *pdata)
{
	struct xgbe_mmc_stats *stats = &pdata->mmc_stats;
	unsigned int mmc_isr = XGMAC_IOREAD(pdata, MMC_TISR);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXOCTETCOUNT_GB))
		stats->txoctetcount_gb +=
			XGMAC_IOREAD(pdata, MMC_TXOCTETCOUNT_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXFRAMECOUNT_GB))
		stats->txframecount_gb +=
			XGMAC_IOREAD(pdata, MMC_TXFRAMECOUNT_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXBROADCASTFRAMES_G))
		stats->txbroadcastframes_g +=
			XGMAC_IOREAD(pdata, MMC_TXBROADCASTFRAMES_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXMULTICASTFRAMES_G))
		stats->txmulticastframes_g +=
			XGMAC_IOREAD(pdata, MMC_TXMULTICASTFRAMES_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX64OCTETS_GB))
		stats->tx64octets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX64OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX65TO127OCTETS_GB))
		stats->tx65to127octets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX65TO127OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX128TO255OCTETS_GB))
		stats->tx128to255octets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX128TO255OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX256TO511OCTETS_GB))
		stats->tx256to511octets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX256TO511OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX512TO1023OCTETS_GB))
		stats->tx512to1023octets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX512TO1023OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TX1024TOMAXOCTETS_GB))
		stats->tx1024tomaxoctets_gb +=
			XGMAC_IOREAD(pdata, MMC_TX1024TOMAXOCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXUNICASTFRAMES_GB))
		stats->txunicastframes_gb +=
			XGMAC_IOREAD(pdata, MMC_TXUNICASTFRAMES_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXMULTICASTFRAMES_GB))
		stats->txmulticastframes_gb +=
			XGMAC_IOREAD(pdata, MMC_TXMULTICASTFRAMES_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXBROADCASTFRAMES_GB))
		stats->txbroadcastframes_g +=
			XGMAC_IOREAD(pdata, MMC_TXBROADCASTFRAMES_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXUNDERFLOWERROR))
		stats->txunderflowerror +=
			XGMAC_IOREAD(pdata, MMC_TXUNDERFLOWERROR_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXOCTETCOUNT_G))
		stats->txoctetcount_g +=
			XGMAC_IOREAD(pdata, MMC_TXOCTETCOUNT_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXFRAMECOUNT_G))
		stats->txframecount_g +=
			XGMAC_IOREAD(pdata, MMC_TXFRAMECOUNT_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXPAUSEFRAMES))
		stats->txpauseframes +=
			XGMAC_IOREAD(pdata, MMC_TXPAUSEFRAMES_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_TISR, TXVLANFRAMES_G))
		stats->txvlanframes_g +=
			XGMAC_IOREAD(pdata, MMC_TXVLANFRAMES_G_LO);
}

static void xgbe_rx_mmc_int(struct xgbe_prv_data *pdata)
{
	struct xgbe_mmc_stats *stats = &pdata->mmc_stats;
	unsigned int mmc_isr = XGMAC_IOREAD(pdata, MMC_RISR);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXFRAMECOUNT_GB))
		stats->rxframecount_gb +=
			XGMAC_IOREAD(pdata, MMC_RXFRAMECOUNT_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXOCTETCOUNT_GB))
		stats->rxoctetcount_gb +=
			XGMAC_IOREAD(pdata, MMC_RXOCTETCOUNT_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXOCTETCOUNT_G))
		stats->rxoctetcount_g +=
			XGMAC_IOREAD(pdata, MMC_RXOCTETCOUNT_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXBROADCASTFRAMES_G))
		stats->rxbroadcastframes_g +=
			XGMAC_IOREAD(pdata, MMC_RXBROADCASTFRAMES_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXMULTICASTFRAMES_G))
		stats->rxmulticastframes_g +=
			XGMAC_IOREAD(pdata, MMC_RXMULTICASTFRAMES_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXCRCERROR))
		stats->rxcrcerror +=
			XGMAC_IOREAD(pdata, MMC_RXCRCERROR_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXRUNTERROR))
		stats->rxrunterror +=
			XGMAC_IOREAD(pdata, MMC_RXRUNTERROR);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXJABBERERROR))
		stats->rxjabbererror +=
			XGMAC_IOREAD(pdata, MMC_RXJABBERERROR);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXUNDERSIZE_G))
		stats->rxundersize_g +=
			XGMAC_IOREAD(pdata, MMC_RXUNDERSIZE_G);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXOVERSIZE_G))
		stats->rxoversize_g +=
			XGMAC_IOREAD(pdata, MMC_RXOVERSIZE_G);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX64OCTETS_GB))
		stats->rx64octets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX64OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX65TO127OCTETS_GB))
		stats->rx65to127octets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX65TO127OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX128TO255OCTETS_GB))
		stats->rx128to255octets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX128TO255OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX256TO511OCTETS_GB))
		stats->rx256to511octets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX256TO511OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX512TO1023OCTETS_GB))
		stats->rx512to1023octets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX512TO1023OCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RX1024TOMAXOCTETS_GB))
		stats->rx1024tomaxoctets_gb +=
			XGMAC_IOREAD(pdata, MMC_RX1024TOMAXOCTETS_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXUNICASTFRAMES_G))
		stats->rxunicastframes_g +=
			XGMAC_IOREAD(pdata, MMC_RXUNICASTFRAMES_G_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXLENGTHERROR))
		stats->rxlengtherror +=
			XGMAC_IOREAD(pdata, MMC_RXLENGTHERROR_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXOUTOFRANGETYPE))
		stats->rxoutofrangetype +=
			XGMAC_IOREAD(pdata, MMC_RXOUTOFRANGETYPE_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXPAUSEFRAMES))
		stats->rxpauseframes +=
			XGMAC_IOREAD(pdata, MMC_RXPAUSEFRAMES_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXFIFOOVERFLOW))
		stats->rxfifooverflow +=
			XGMAC_IOREAD(pdata, MMC_RXFIFOOVERFLOW_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXVLANFRAMES_GB))
		stats->rxvlanframes_gb +=
			XGMAC_IOREAD(pdata, MMC_RXVLANFRAMES_GB_LO);

	if (XGMAC_GET_BITS(mmc_isr, MMC_RISR, RXWATCHDOGERROR))
		stats->rxwatchdogerror +=
			XGMAC_IOREAD(pdata, MMC_RXWATCHDOGERROR);
}

static void xgbe_read_mmc_stats(struct xgbe_prv_data *pdata)
{
	struct xgbe_mmc_stats *stats = &pdata->mmc_stats;

	/* Freeze counters */
	XGMAC_IOWRITE_BITS(pdata, MMC_CR, MCF, 1);

	stats->txoctetcount_gb +=
		XGMAC_IOREAD(pdata, MMC_TXOCTETCOUNT_GB_LO);

	stats->txframecount_gb +=
		XGMAC_IOREAD(pdata, MMC_TXFRAMECOUNT_GB_LO);

	stats->txbroadcastframes_g +=
		XGMAC_IOREAD(pdata, MMC_TXBROADCASTFRAMES_G_LO);

	stats->txmulticastframes_g +=
		XGMAC_IOREAD(pdata, MMC_TXMULTICASTFRAMES_G_LO);

	stats->tx64octets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX64OCTETS_GB_LO);

	stats->tx65to127octets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX65TO127OCTETS_GB_LO);

	stats->tx128to255octets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX128TO255OCTETS_GB_LO);

	stats->tx256to511octets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX256TO511OCTETS_GB_LO);

	stats->tx512to1023octets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX512TO1023OCTETS_GB_LO);

	stats->tx1024tomaxoctets_gb +=
		XGMAC_IOREAD(pdata, MMC_TX1024TOMAXOCTETS_GB_LO);

	stats->txunicastframes_gb +=
		XGMAC_IOREAD(pdata, MMC_TXUNICASTFRAMES_GB_LO);

	stats->txmulticastframes_gb +=
		XGMAC_IOREAD(pdata, MMC_TXMULTICASTFRAMES_GB_LO);

	stats->txbroadcastframes_g +=
		XGMAC_IOREAD(pdata, MMC_TXBROADCASTFRAMES_GB_LO);

	stats->txunderflowerror +=
		XGMAC_IOREAD(pdata, MMC_TXUNDERFLOWERROR_LO);

	stats->txoctetcount_g +=
		XGMAC_IOREAD(pdata, MMC_TXOCTETCOUNT_G_LO);

	stats->txframecount_g +=
		XGMAC_IOREAD(pdata, MMC_TXFRAMECOUNT_G_LO);

	stats->txpauseframes +=
		XGMAC_IOREAD(pdata, MMC_TXPAUSEFRAMES_LO);

	stats->txvlanframes_g +=
		XGMAC_IOREAD(pdata, MMC_TXVLANFRAMES_G_LO);

	stats->rxframecount_gb +=
		XGMAC_IOREAD(pdata, MMC_RXFRAMECOUNT_GB_LO);

	stats->rxoctetcount_gb +=
		XGMAC_IOREAD(pdata, MMC_RXOCTETCOUNT_GB_LO);

	stats->rxoctetcount_g +=
		XGMAC_IOREAD(pdata, MMC_RXOCTETCOUNT_G_LO);

	stats->rxbroadcastframes_g +=
		XGMAC_IOREAD(pdata, MMC_RXBROADCASTFRAMES_G_LO);

	stats->rxmulticastframes_g +=
		XGMAC_IOREAD(pdata, MMC_RXMULTICASTFRAMES_G_LO);

	stats->rxcrcerror +=
		XGMAC_IOREAD(pdata, MMC_RXCRCERROR_LO);

	stats->rxrunterror +=
		XGMAC_IOREAD(pdata, MMC_RXRUNTERROR);

	stats->rxjabbererror +=
		XGMAC_IOREAD(pdata, MMC_RXJABBERERROR);

	stats->rxundersize_g +=
		XGMAC_IOREAD(pdata, MMC_RXUNDERSIZE_G);

	stats->rxoversize_g +=
		XGMAC_IOREAD(pdata, MMC_RXOVERSIZE_G);

	stats->rx64octets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX64OCTETS_GB_LO);

	stats->rx65to127octets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX65TO127OCTETS_GB_LO);

	stats->rx128to255octets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX128TO255OCTETS_GB_LO);

	stats->rx256to511octets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX256TO511OCTETS_GB_LO);

	stats->rx512to1023octets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX512TO1023OCTETS_GB_LO);

	stats->rx1024tomaxoctets_gb +=
		XGMAC_IOREAD(pdata, MMC_RX1024TOMAXOCTETS_GB_LO);

	stats->rxunicastframes_g +=
		XGMAC_IOREAD(pdata, MMC_RXUNICASTFRAMES_G_LO);

	stats->rxlengtherror +=
		XGMAC_IOREAD(pdata, MMC_RXLENGTHERROR_LO);

	stats->rxoutofrangetype +=
		XGMAC_IOREAD(pdata, MMC_RXOUTOFRANGETYPE_LO);

	stats->rxpauseframes +=
		XGMAC_IOREAD(pdata, MMC_RXPAUSEFRAMES_LO);

	stats->rxfifooverflow +=
		XGMAC_IOREAD(pdata, MMC_RXFIFOOVERFLOW_LO);

	stats->rxvlanframes_gb +=
		XGMAC_IOREAD(pdata, MMC_RXVLANFRAMES_GB_LO);

	stats->rxwatchdogerror +=
		XGMAC_IOREAD(pdata, MMC_RXWATCHDOGERROR);

	/* Un-freeze counters */
	XGMAC_IOWRITE_BITS(pdata, MMC_CR, MCF, 0);
}

static void xgbe_config_mmc(struct xgbe_prv_data *pdata)
{
	/* Set counters to reset on read */
	XGMAC_IOWRITE_BITS(pdata, MMC_CR, ROR, 1);

	/* Reset the counters */
	XGMAC_IOWRITE_BITS(pdata, MMC_CR, CR, 1);
}

static void xgbe_enable_tx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Enable each Tx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, ST, 1);
	}

	/* Enable each Tx queue */
	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TXQEN,
				       MTL_Q_ENABLED);

	/* Enable MAC Tx */
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, TE, 1);
}

static void xgbe_disable_tx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Disable MAC Tx */
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, TE, 0);

	/* Disable each Tx queue */
	for (i = 0; i < pdata->hw_feat.tx_q_cnt; i++)
		XGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TXQEN, 0);

	/* Disable each Tx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, ST, 0);
	}
}

static void xgbe_enable_rx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int reg_val, i;

	/* Enable each Rx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, SR, 1);
	}

	/* Enable each Rx queue */
	reg_val = 0;
	for (i = 0; i < pdata->hw_feat.rx_q_cnt; i++)
		reg_val |= (0x02 << (i << 1));
	XGMAC_IOWRITE(pdata, MAC_RQC0R, reg_val);

	/* Enable MAC Rx */
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, DCRCC, 1);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, CST, 1);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, ACS, 1);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, RE, 1);
}

static void xgbe_disable_rx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Disable MAC Rx */
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, DCRCC, 0);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, CST, 0);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, ACS, 0);
	XGMAC_IOWRITE_BITS(pdata, MAC_RCR, RE, 0);

	/* Disable each Rx queue */
	XGMAC_IOWRITE(pdata, MAC_RQC0R, 0);

	/* Disable each Rx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, SR, 0);
	}
}

static void xgbe_powerup_tx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Enable each Tx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, ST, 1);
	}

	/* Enable MAC Tx */
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, TE, 1);
}

static void xgbe_powerdown_tx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Disable MAC Tx */
	XGMAC_IOWRITE_BITS(pdata, MAC_TCR, TE, 0);

	/* Disable each Tx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->tx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_TCR, ST, 0);
	}
}

static void xgbe_powerup_rx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Enable each Rx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, SR, 1);
	}
}

static void xgbe_powerdown_rx(struct xgbe_prv_data *pdata)
{
	struct xgbe_channel *channel;
	unsigned int i;

	/* Disable each Rx DMA channel */
	channel = pdata->channel;
	for (i = 0; i < pdata->channel_count; i++, channel++) {
		if (!channel->rx_ring)
			break;

		XGMAC_DMA_IOWRITE_BITS(channel, DMA_CH_RCR, SR, 0);
	}
}

static int xgbe_init(struct xgbe_prv_data *pdata)
{
	struct xgbe_desc_if *desc_if = &pdata->desc_if;
	int ret;

	DBGPR("-->xgbe_init\n");

	/* Flush Tx queues */
	ret = xgbe_flush_tx_queues(pdata);
	if (ret)
		return ret;

	/*
	 * Initialize DMA related features
	 */
	xgbe_config_dma_bus(pdata);
	xgbe_config_dma_cache(pdata);
	xgbe_config_osp_mode(pdata);
	xgbe_config_pblx8(pdata);
	xgbe_config_tx_pbl_val(pdata);
	xgbe_config_rx_pbl_val(pdata);
	xgbe_config_rx_coalesce(pdata);
	xgbe_config_tx_coalesce(pdata);
	xgbe_config_rx_buffer_size(pdata);
	xgbe_config_tso_mode(pdata);
	desc_if->wrapper_tx_desc_init(pdata);
	desc_if->wrapper_rx_desc_init(pdata);
	xgbe_enable_dma_interrupts(pdata);

	/*
	 * Initialize MTL related features
	 */
	xgbe_config_mtl_mode(pdata);
	xgbe_config_rx_queue_mapping(pdata);
	/*TODO: Program the priorities mapped to the Selected Traffic Classes
		in MTL_TC_Prty_Map0-3 registers */
	xgbe_config_tsf_mode(pdata, pdata->tx_sf_mode);
	xgbe_config_rsf_mode(pdata, pdata->rx_sf_mode);
	xgbe_config_tx_threshold(pdata, pdata->tx_threshold);
	xgbe_config_rx_threshold(pdata, pdata->rx_threshold);
	xgbe_config_tx_fifo_size(pdata);
	xgbe_config_rx_fifo_size(pdata);
	xgbe_config_flow_control_threshold(pdata);
	/*TODO: Queue to Traffic Class Mapping (Q2TCMAP) */
	/*TODO: Error Packet and undersized good Packet forwarding enable
		(FEP and FUP)
	 */
	xgbe_enable_mtl_interrupts(pdata);

	/* Transmit Class Weight */
	XGMAC_IOWRITE_BITS(pdata, MTL_Q_TCQWR, QW, 0x10);

	/*
	 * Initialize MAC related features
	 */
	xgbe_config_mac_address(pdata);
	xgbe_config_jumbo_enable(pdata);
	xgbe_config_flow_control(pdata);
	xgbe_config_checksum_offload(pdata);
	xgbe_config_vlan_support(pdata);
	xgbe_config_mmc(pdata);
	xgbe_enable_mac_interrupts(pdata);

	DBGPR("<--xgbe_init\n");

	return 0;
}

void xgbe_init_function_ptrs_dev(struct xgbe_hw_if *hw_if)
{
	DBGPR("-->xgbe_init_function_ptrs\n");

	hw_if->tx_complete = xgbe_tx_complete;

	hw_if->set_promiscuous_mode = xgbe_set_promiscuous_mode;
	hw_if->set_all_multicast_mode = xgbe_set_all_multicast_mode;
	hw_if->set_addn_mac_addrs = xgbe_set_addn_mac_addrs;
	hw_if->set_mac_address = xgbe_set_mac_address;

	hw_if->enable_rx_csum = xgbe_enable_rx_csum;
	hw_if->disable_rx_csum = xgbe_disable_rx_csum;

	hw_if->enable_rx_vlan_stripping = xgbe_enable_rx_vlan_stripping;
	hw_if->disable_rx_vlan_stripping = xgbe_disable_rx_vlan_stripping;

	hw_if->read_mmd_regs = xgbe_read_mmd_regs;
	hw_if->write_mmd_regs = xgbe_write_mmd_regs;

	hw_if->set_gmii_speed = xgbe_set_gmii_speed;
	hw_if->set_gmii_2500_speed = xgbe_set_gmii_2500_speed;
	hw_if->set_xgmii_speed = xgbe_set_xgmii_speed;

	hw_if->enable_tx = xgbe_enable_tx;
	hw_if->disable_tx = xgbe_disable_tx;
	hw_if->enable_rx = xgbe_enable_rx;
	hw_if->disable_rx = xgbe_disable_rx;

	hw_if->powerup_tx = xgbe_powerup_tx;
	hw_if->powerdown_tx = xgbe_powerdown_tx;
	hw_if->powerup_rx = xgbe_powerup_rx;
	hw_if->powerdown_rx = xgbe_powerdown_rx;

	hw_if->pre_xmit = xgbe_pre_xmit;
	hw_if->dev_read = xgbe_dev_read;
	hw_if->enable_int = xgbe_enable_int;
	hw_if->disable_int = xgbe_disable_int;
	hw_if->init = xgbe_init;
	hw_if->exit = xgbe_exit;

	/* Descriptor related Sequences have to be initialized here */
	hw_if->tx_desc_init = xgbe_tx_desc_init;
	hw_if->rx_desc_init = xgbe_rx_desc_init;
	hw_if->tx_desc_reset = xgbe_tx_desc_reset;
	hw_if->rx_desc_reset = xgbe_rx_desc_reset;
	hw_if->is_last_desc = xgbe_is_last_desc;
	hw_if->is_context_desc = xgbe_is_context_desc;

	/* For FLOW ctrl */
	hw_if->config_tx_flow_control = xgbe_config_tx_flow_control;
	hw_if->config_rx_flow_control = xgbe_config_rx_flow_control;

	/* For RX coalescing */
	hw_if->config_rx_coalesce = xgbe_config_rx_coalesce;
	hw_if->config_tx_coalesce = xgbe_config_tx_coalesce;
	hw_if->usec_to_riwt = xgbe_usec_to_riwt;
	hw_if->riwt_to_usec = xgbe_riwt_to_usec;

	/* For RX and TX threshold config */
	hw_if->config_rx_threshold = xgbe_config_rx_threshold;
	hw_if->config_tx_threshold = xgbe_config_tx_threshold;

	/* For RX and TX Store and Forward Mode config */
	hw_if->config_rsf_mode = xgbe_config_rsf_mode;
	hw_if->config_tsf_mode = xgbe_config_tsf_mode;

	/* For TX DMA Operating on Second Frame config */
	hw_if->config_osp_mode = xgbe_config_osp_mode;

	/* For RX and TX PBL config */
	hw_if->config_rx_pbl_val = xgbe_config_rx_pbl_val;
	hw_if->get_rx_pbl_val = xgbe_get_rx_pbl_val;
	hw_if->config_tx_pbl_val = xgbe_config_tx_pbl_val;
	hw_if->get_tx_pbl_val = xgbe_get_tx_pbl_val;
	hw_if->config_pblx8 = xgbe_config_pblx8;

	/* For MMC statistics support */
	hw_if->tx_mmc_int = xgbe_tx_mmc_int;
	hw_if->rx_mmc_int = xgbe_rx_mmc_int;
	hw_if->read_mmc_stats = xgbe_read_mmc_stats;

	DBGPR("<--xgbe_init_function_ptrs\n");
}
