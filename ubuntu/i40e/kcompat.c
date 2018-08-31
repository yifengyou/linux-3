/*
 * Compatibility layer
 * Copyright (c) 2018 Juerg Haefliger <juergh@canonical.com>
 */

#include <linux/net.h>

/* cherry picked from v4.4 include/linux/netdevice.h */
#define NETDEV_RSS_KEY_LEN 52

/* backported from v4.4 net/core/ethtool.c */
void netdev_rss_key_fill(void *buffer, size_t len)
{
	static u8 netdev_rss_key[NETDEV_RSS_KEY_LEN];

	BUG_ON(len > NETDEV_RSS_KEY_LEN);
	net_get_random_once(netdev_rss_key, sizeof(netdev_rss_key));
	memcpy(buffer, netdev_rss_key, len);
}
