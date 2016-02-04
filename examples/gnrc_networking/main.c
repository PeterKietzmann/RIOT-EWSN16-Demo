/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Example application for demonstrating the RIOT network stack
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>

#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc/ipv6/blacklist.h"

#include "net/gnrc/rpl.h"
#include "shell.h"
#include "msg.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int udp_cmd(int argc, char **argv);


int start_trail(int argc, char **argv)
{
	if ((argc > 1) && (strcmp("0", argv[1]) == 0)) {
		perform_trail(0);
		return 0;	
	}
	
	perform_trail(1);
	return 0;
}

int attack(int argc, char **argv)
{	
	if (argc > 2) {
		int do_it = atoi(argv[1]);
		int rank = atoi(argv[2]);
		perform_attack( (uint8_t)do_it, (uint16_t)(rank));
	}
	return 0;
}

/*
fe80::585a:6667:bdbf:3702
fe80::5855:5477:ade:6a42
fe80::5855:4257:5893:364a
fe80::585a:6a65:70bd:247e
fe80::5855:5a4b:7dd5:425a
*/

int szenario1(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    kernel_pid_t iface_pid = (kernel_pid_t)7;
    gnrc_rpl_init(iface_pid);

    uint16_t me_is = byteorder_ntohs(my_linklocal_address.u16[7]);
    switch (me_is)
    {
        case 0x247e: { // fe80::585a:6a65:70bd:247e
            // root
            ipv6_addr_t addr;
            ipv6_addr_from_str(&addr, "2001::1");
            gnrc_ipv6_netif_add_addr(iface_pid, &addr, 64, GNRC_IPV6_NETIF_ADDR_FLAGS_UNICAST);

            // ignore all leafs
            ipv6_addr_t ignr_addr;
            ipv6_addr_from_str(&ignr_addr, "fe80::5855:5477:ade:6a42");
            gnrc_ipv6_blacklist_add(&ignr_addr);

            ipv6_addr_from_str(&ignr_addr, "fe80::5855:4257:5893:364a");
            gnrc_ipv6_blacklist_add(&ignr_addr);

            ipv6_addr_from_str(&ignr_addr, "fe80::5855:5a4b:7dd5:425a");
            gnrc_ipv6_blacklist_add(&ignr_addr);        
            break;
        }
        case 0x3702: {// fe80::585a:6667:bdbf:3702
                // one hop to root
                ipv6_addr_t ignr_addr;
                ipv6_addr_from_str(&ignr_addr, "fe80::5855:4257:5893:364a");
                gnrc_ipv6_blacklist_add(&ignr_addr);
                
                break;
            }
        case 0x6a42: {// fe80::5855:5477:ade:6a42
                // right leaf
                ipv6_addr_t ignr_addr;
                ipv6_addr_from_str(&ignr_addr, "fe80::585a:6a65:70bd:247e");
                gnrc_ipv6_blacklist_add(&ignr_addr);
        
                break;
            }
        case 0x425a: {// fe80::5855:5a4b:7dd5:425a
            // left leaf
            ipv6_addr_t ignr_addr;
            ipv6_addr_from_str(&ignr_addr, "fe80::585a:6a65:70bd:247e");
            gnrc_ipv6_blacklist_add(&ignr_addr);
            
            break;
            }
        case 0x364a:{ // fe80::5855:4257:5893:364a
                // middle leaf (attacker)
                ipv6_addr_t ignr_addr;
                ipv6_addr_from_str(&ignr_addr, "fe80::585a:6a65:70bd:247e");
                gnrc_ipv6_blacklist_add(&ignr_addr);
        
                ipv6_addr_from_str(&ignr_addr, "fe80::585a:6667:bdbf:3702");
                gnrc_ipv6_blacklist_add(&ignr_addr);
        
                break;
            }


        default:
        break;
    }

    return 0;
}

int root_start(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint16_t me_is = byteorder_ntohs(my_linklocal_address.u16[7]);
    if (me_is == 0x247e) {
        uint8_t instance_id = (uint8_t)1;
        ipv6_addr_t dodag_id;
        ipv6_addr_from_str(&dodag_id, "2001::1");
        gnrc_rpl_root_init(instance_id, &dodag_id, false, false);

    } else {
        puts("It wasn't me.");
    }
    return 0;
}

int attack_auto(int argc, char **argv)
{
    uint16_t me_is = byteorder_ntohs(my_linklocal_address.u16[7]);
   if (argc > 2) {
        ipv6_addr_t addr;
        ipv6_addr_from_str(&addr, argv[1]);
        int rank = atoi(argv[2]);
        if (me_is == byteorder_ntohs(addr.u16[7])) 
        {
            perform_attack( (uint8_t)1, (uint16_t)(rank));
        }
    } else {
        if (me_is == 0x425a) 
        {
            perform_attack( (uint8_t)1, 300);
        }
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    { "trail", "activate TRAIL", start_trail },
    { "attack", "start attack with given rank TRAIL", attack },
    { "attack_auto", "start attack on given node", attack_auto },
    { "sze1", "start szenario1", szenario1 },
    { "root_start", "start root node", root_start },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT network stack example application");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
