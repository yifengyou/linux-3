/*
 * Compatibility layer
 * Copyright (c) 2018 Juerg Haefliger <juergh@canonical.com>
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#define napi_schedule_irqoff	napi_schedule

#define smp_mb__before_atomic	smp_mb
#define smp_mb__after_atomic	smp_mb

#define netdev_phys_item_id	netdev_phys_port_id

#define NETIF_F_GSO_UDP_TUNNEL_CSUM	0
#define NETIF_F_SCTP_CRC		NETIF_F_SCTP_CSUM

#define SKB_GSO_UDP_TUNNEL_CSUM	0

#define hlist_add_behind(a, b)	hlist_add_after((b), (a))

#define dev_consume_skb_any	dev_kfree_skb_any

#define dma_rmb	rmb

#define napi_complete_done(napi, work_done)	napi_complete((napi))

#define skb_vlan_tag_present	vlan_tx_tag_present
#define skb_vlan_tag_get	vlan_tx_tag_get

#define timespec64		timespec
#define ns_to_timespec64	ns_to_timespec
#define timespec64_to_ns	timespec_to_ns
#define timespec64_add		timespec_add
#define ktime_to_timespec64	ktime_to_timespec

/* cherry picked from v4.4 include/linux/skbuff.h */
static inline int skb_put_padto(struct sk_buff *skb, unsigned int len)
{
	unsigned int size = skb->len;

	if (unlikely(size < len)) {
		len -= size;
		if (skb_pad(skb, len))
			return -ENOMEM;
		__skb_put(skb, len);
	}
	return 0;
}

/*
 * backported from v4.9 net/ethernet/eth.c
 * 3.13 doesn't support CONFIG_OF so the function always returns -ENODEV
 */
static inline int eth_platform_get_mac_address(struct device *dev,
					       u8 *mac_addr)
{
	return -ENODEV;
}

/* The following are defined in kompat.c */
extern void netdev_rss_key_fill(void *buffer, size_t len);

#endif /* _KCOMPAT_H_ */
