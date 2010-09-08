/*
 *  Universal TUN/TAP device driver.
 *
 *  Multithreaded STREAMS tun pseudo device driver.
 *
 *  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: if_tun.h,v 1.4 2000/05/01 12:23:27 maxk Exp 
 */

/*
 *  Modified by: Kazuyoshi <admin2@whiteboard.ne.jp>
 *  Modified for supporting Ethernet tunneling as known as TAP.
 *  $Date: 2009/06/07 06:28:43 $, $Revision: 1.3 $
 */

#ifndef	_SYS_IF_TUN_H
#define	_SYS_IF_TUN_H

#ifdef _KERNEL
/* Uncomment to enable debuging */
//#define TUN_DEBUG 1

#ifdef TUN_DEBUG
#define DBG	 cmn_err
#else
#define DBG( a... )
#endif

/* PPA structure, one per TUN iface */ 
struct tunppa {
  unsigned int id;    		/* Iface number		*/
  queue_t *rq;			/* Control Stream RQ    */
  struct tunstr * p_str; 	/* Protocol Streams 	*/
#ifdef TUNTAP_TAP
    struct ether_addr  etheraddr;  /* Ethernet Address */
#endif    
}; 
#define TUNMAXPPA	20

/* Stream structure, one per Stream */
struct tunstr {
  struct tunstr	*s_next;	/* next in streams list */
  struct tunstr	*p_next;	/* next in ppa list */
  queue_t *rq;			/* pointer to rq */

  struct tunppa *ppa;		/* assigned PPA */
  u_long flags;			/* flags */
  u_long state;			/* DL state */
  u_long sap;			/* bound sap */
  u_long minor;			/* minor device number */
};

/* Flags */
#define TUN_CONTROL	0x0001

#define TUN_RAW		0x0100
#define TUN_FAST	0x0200

#define TUN_ALL_PHY	0x0010
#define TUN_ALL_SAP	0x0020
#define TUN_ALL_MUL	0x0040

#define SNIFFER(a) ( (a & TUN_ALL_SAP) || (a & TUN_ALL_PHY) )

struct tundladdr {
#ifdef TUNTAP_TAP    
  struct ether_addr  etheraddr;
#endif    
  u_short sap;
};
#define TUN_ADDR_LEN  	(sizeof(struct tundladdr))

#define TUN_QUEUE	0
#define TUN_DROP	1

#endif /* _KERNEL */

/* IOCTL defines */
#define TUNNEWPPA	(('T'<<16) | 0x0001)
#define TUNSETPPA	(('T'<<16) | 0x0002)

#endif	/* _SYS_IF_TUN_H */
