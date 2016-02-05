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

int tabula_rasa(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    drain_lifetime_of_all_parents();
    return 0;
}

int vampire(int argc, char **argv)
{
    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    
    ipv6_addr_t addr;
    if( argc < 2 ) {
        puts("missing <addr> parameter!");
        return 1;
    }
    
    if (ipv6_addr_from_str(&addr, argv[1]) == NULL) {
        puts("error: unable to parse IPv6 address.");
        return 1;
    }
    
    ipv6_addr_to_str(ipv6_addr, &addr, IPV6_ADDR_MAX_STR_LEN);
    printf("drain life from: %s\n", ipv6_addr);
                
    drain_lifetime_of_parent(&addr);
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    { "trail", "activate TRAIL", start_trail },
    { "attack", "start attack with given rank TRAIL", attack },
    { "tabula_rasa", "suck the life of all parents TRAIL", tabula_rasa },
    { "vampire", "<addr> suck the life of one parent TRAIL", vampire },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT network stack example application");
puts("NEW");
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
