/*
 * Copyright (C) 2015 Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  Cenk Gündoğan <cnkgndgn@gmail.com>
 */

#include "net/icmpv6.h"
#include "net/ipv6.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/ipv6/netif.h"
#include "net/gnrc/icmpv6.h"
#include "net/gnrc.h"
#include "mutex.h"

#include "net/gnrc/rpl.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static char _stack[GNRC_RPL_STACK_SIZE];
kernel_pid_t gnrc_rpl_pid = KERNEL_PID_UNDEF;
static uint32_t _lt_time = GNRC_RPL_LIFETIME_UPDATE_STEP * SEC_IN_USEC;
static xtimer_t _lt_timer;
static msg_t _lt_msg = { .type = GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE };
static msg_t _msg_q[GNRC_RPL_MSG_QUEUE_SIZE];
static gnrc_netreg_entry_t _me_reg;
static mutex_t _inst_id_mutex = MUTEX_INIT;
static uint8_t _instance_id;

gnrc_rpl_instance_t gnrc_rpl_instances[GNRC_RPL_INSTANCES_NUMOF];
gnrc_rpl_parent_t gnrc_rpl_parents[GNRC_RPL_PARENTS_NUMOF];

static void _update_lifetime(void);
static void _dao_handle_send(gnrc_rpl_dodag_t *dodag);
static void _receive(gnrc_pktsnip_t *pkt);
static void *_event_loop(void *args);


#define TVO_DELAY_STACKSIZE (3072)
char tvo_delay_over_buf[TVO_DELAY_STACKSIZE]; // trail
kernel_pid_t tvo_delay_over_pid = KERNEL_PID_UNDEF; // trail
xtimer_t tvo_timer; // trail
uint32_t tvo_resend_seconds; // trail
uint32_t tvo_resend_micro; // trail: random micro delay
timex_t tvo_time; // trail

uint16_t global_tvo_counter = 1; // trail

//rpl_dodag_trail_t trail_temp_dodag; // trail
gnrc_rpl_dodag_trail_t trail_parent_buffer[RPL_MAX_PARENTS]; //trail: buffer parents when receiving DIOs

uint8_t tvo_sequence_number = 0; // trail
//uint8_t tvo_pending = 1; // trail: defines if a verification is pending
//uint8_t tvo_parent_verified = 1; // trail: defines if a verification is pending
uint8_t do_trail = 1; // trail: enables / disables trail on startup
uint8_t attacker = 0; // trail: enables / disables attacker mode on startup
uint16_t attacker_rank = 0; // trail: rank of the attacker -> is constant
uint16_t ignore_root_addr = 0;

uint8_t attacker_dodag = 0; // trail
uint16_t attacker_dodag_rank = 0; // trail

struct rpl_tvo_local_t tvo_local_buffer[TVO_LOCAL_BUFFER_LEN]; //trail
uint8_t tvo_local_flags[TVO_LOCAL_BUFFER_LEN]; //trail

/* helper for TRAIL legacy migration */

static mutex_t _get_my_instance_mutex = MUTEX_INIT;
/**
 * @return the FIRST RPL instance of this node that is active 
 */
static gnrc_rpl_instance_t* _get_my_instance(void)
{
    mutex_lock(&_get_my_instance_mutex);
    gnrc_rpl_instance_t *inst;
    for (int i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        inst = &gnrc_rpl_instances[i];
        if (inst->state != 0) {
            mutex_unlock(&_get_my_instance_mutex);
            return inst;
        }
    }
    mutex_unlock(&_get_my_instance_mutex);
    return NULL;
}

static mutex_t rpl_get_my_dodag_mutex = MUTEX_INIT;
/**
 * @return the DODAG of the first instance of this node
 */
static gnrc_rpl_dodag_t* rpl_get_my_dodag(void)
{
    mutex_lock(&rpl_get_my_dodag_mutex);
    gnrc_rpl_instance_t *inst = _get_my_instance();
    if (inst != NULL) {
        mutex_unlock(&rpl_get_my_dodag_mutex);
        return &(inst->dodag);
    }
    mutex_unlock(&rpl_get_my_dodag_mutex);
    return NULL;
}

static mutex_t get_my_ipv6_address_mutex = MUTEX_INIT;
/**
 * @return the IPv6 address for this node on the first available interface
 */
ipv6_addr_t* get_my_ipv6_address(ipv6_addr_t* my_address)
{
    mutex_lock(&get_my_ipv6_address_mutex);
    kernel_pid_t iface = KERNEL_PID_UNDEF;
    kernel_pid_t ifs[GNRC_NETIF_NUMOF];
    size_t numof = gnrc_netif_get(ifs);

    for (size_t i = 0; i < numof && i < GNRC_NETIF_NUMOF; i++) {
        iface = ifs[i];
    }
    gnrc_ipv6_netif_t *entry = gnrc_ipv6_netif_get(iface);
    for (int i = 0; i < GNRC_IPV6_NETIF_ADDR_NUMOF; i++) {
        if (!ipv6_addr_is_unspecified(&entry->addrs[i].addr)) {
            memcpy(my_address, &(entry->addrs[i].addr), sizeof(*my_address));
            mutex_unlock(&get_my_ipv6_address_mutex);
            return my_address;
        }
    }
    mutex_unlock(&get_my_ipv6_address_mutex);
    return NULL;
}

static mutex_t rpl_find_parent_mutex = MUTEX_INIT;
/**
 * @return the parent matching the given IPv6 address
 */
gnrc_rpl_parent_t *rpl_find_parent(ipv6_addr_t* src_addr)
{
    gnrc_rpl_parent_t *parent;
    mutex_lock(&rpl_find_parent_mutex);
    for (uint8_t i = 0; i < GNRC_RPL_PARENTS_NUMOF; ++i) {
        parent = &gnrc_rpl_parents[i];
        if (ipv6_addr_equal(&(parent->addr), src_addr) == (sizeof(*src_addr)<<3) ) {
            mutex_unlock(&rpl_find_parent_mutex);
            return parent;
        }
    }
    mutex_unlock(&rpl_find_parent_mutex);
    return NULL;
}

/**
 * @brief set the rank of this node manualy
 */
void change_rank(uint16_t new_rank)
{
    gnrc_rpl_dodag_t *mydodag;
    mydodag = rpl_get_my_dodag();

    if (mydodag != NULL) {
        mydodag->my_rank = new_rank;
        //mydodag->min_rank = new_rank;
        printf("Calculated rank to %u (manually reset rank)\n" , mydodag->my_rank);
    }
    puts("ERROR: no DODAG available to set rank");
}

/**
 * @brief ignore the RPL root address, identified using the last 2 bytes
 */
void ignore_root(uint16_t root_addr)
{
    ignore_root_addr = root_addr;
}


//trail
void* tvo_delay_over(void* args){
    (void)args;

xtimer_t tvo_timer_local; // trail

        while(1){
                thread_sleep();
                //if((tvo_ack_received == false) && (tvo_counter < TVO_SEND_RETRIES)){
         //       if(tvo_counter < TVO_SEND_RETRIES){
 //                       tvo_counter++;
                        //rpl_dodag_t * mydodag = rpl_get_my_dodag();

/*
                        struct rpl_tvo_t tvo;
                        //rpl_tvo_init(&tvo);

                        memcpy(&tvo, tvo_resend, sizeof(tvo));

                        //printf("\n(checking trickle) tvo_nonce: %u, tvo_rank: %u, resend_nonce: %u, resend_rank: %u \n\n", tvo.nonce, tvo.rank, tvo_resend->nonce, tvo_resend->rank);

                        printf("*RE*");
                        send_TVO(&(tvo_resend->dst_addr), &tvo, NULL);
*/
                        resend_tvos();
                        /*
                        xtimer_set_wakeup(xtimer_t *timer, uint32_t offset, tvo_delay_over_pid);
                        tvo_time = timex_set(tvo_resend_seconds, tvo_resend_micro);
                        vtimer_remove(&tvo_timer);
                        vtimer_set_wakeup(&tvo_timer, tvo_time, tvo_delay_over_pid);
                        */
                        xtimer_remove(&tvo_timer_local);
                        xtimer_set_wakeup(&tvo_timer_local, (tvo_resend_seconds*SEC_IN_USEC +tvo_resend_micro), tvo_delay_over_pid);
    //            }
        //        else if (tvo_ack_received == false){
        //                long_delay_tvo();
        //        }
        }
        return NULL;
}

//trail
void delay_tvo(uint32_t seconds){

	//delay tvos differently: reduce risk of collisions by neighbors
	timex_t now;
    xtimer_now_timex(&now);
    
	srand(now.microseconds);
	uint32_t random = rand() % 1000000;

	printf("setting new TVO delay to %u seconds and %u ms\n", (unsigned int)seconds, (unsigned int)(random/1000));
	//tvo_time = timex_set(seconds,random);
    tvo_resend_seconds = seconds;
    tvo_resend_micro = random;
//    tvo_counter = 0;
    //tvo_ack_received = false;
    xtimer_remove(&tvo_timer);
    
    xtimer_set_wakeup(&tvo_timer, (tvo_resend_seconds*SEC_IN_USEC +tvo_resend_micro), tvo_delay_over_pid);
}


/**
 * @brief initialize TVO manually
 */
struct rpl_tvo_t * rpl_tvo_manual_init(struct rpl_tvo_t * tvo)
{
    ipv6_addr_t my_address;
    if ( get_my_ipv6_address(&my_address) == NULL ) {
        return NULL;
    }


   // gnrc_rpl_dodag_t *my_dodag = rpl_get_my_dodag();

    tvo->nonce = xtimer_now();
    tvo->rank = 0;
    tvo->rpl_instanceid = 99;//my_dodag->instance->id;
    tvo->s_flag = 0;
    tvo->src_addr = my_address;
    //TODO uncomment for source routing
//	tvo->srh_list[0].addr = my_address;
//	tvo->srh_list_size = 1;
    tvo->tvo_seq = global_tvo_counter + 100;
    global_tvo_counter++;
    tvo->version_number = 66;//my_dodag->version;
    return tvo;
}

/**
 * @brief initialize TVO automatically
 */
struct rpl_tvo_t * rpl_tvo_auto_init(struct rpl_tvo_t * tvo, uint8_t instance, uint8_t version_number)
{

    ipv6_addr_t my_address;
    if ( get_my_ipv6_address(&my_address) == NULL ) {
        return NULL;
    }

    tvo->nonce = xtimer_now();

    tvo->rank = 0;
    tvo->rpl_instanceid = instance;

    tvo->s_flag = 0;
    tvo->src_addr = my_address;

    tvo->tvo_seq = tvo_sequence_number;
    tvo_sequence_number++;
    tvo->version_number = version_number;
    return tvo;
}

/**
 * @brief set if TRAIL autostarts
 */
void start_with_trail(void){
    do_trail = 1;
    printf("TRAIL enabled\n");
}

void rpl_set_attacker(uint16_t rank){
	attacker_dodag = 1;
	attacker_dodag_rank = rank;
}

/**
 * @brief enable Attacker using the specified rank
 */
void start_as_attacker(uint16_t rank){
	attacker = 1;
	attacker_rank = rank;
	rpl_set_attacker(rank);
	printf("Attacker enabled with rank %u\n",rank);
}

/**
 * @brief handle received TVO-ACK
 */
void tvo_ack_has_been_received(ipv6_addr_t *source, uint8_t tvo_seq)
{
	uint16_t i;

	for(i=0;i<TVO_LOCAL_BUFFER_LEN;i++)
	{
		if(tvo_local_buffer[i].tvo_seq == tvo_seq && tvo_local_buffer[i].dst_addr.u8[15] == source->u8[15]){
			printf("freeing tvo buffer at %u\n",i);
			tvo_local_flags[i] = 0; //free array index
		}
	//	if(tvo_local_buffer[i].his_tvo_seq == tvo_seq && tvo_local_buffer[i].dst_addr.uint8[15] == source->uint8[15]){
	//		printf("freeing tvo buffer at %u\n",i);
	//		tvo_local_flags[i] = 0; //free array index
	//	}
	}
}

/**
 * @brief handle received TVO
 */
struct rpl_tvo_local_t * has_tvo_been_received(ipv6_addr_t * source, uint8_t tvo_seq)
{
	uint16_t i;

	for(i=0;i<TVO_LOCAL_BUFFER_LEN;i++)
	{
		if(tvo_local_buffer[i].his_tvo_seq == tvo_seq && tvo_local_buffer[i].prev_hop_addr.u8[15] == source->u8[15]){
			return &tvo_local_buffer[i];
		}
	}
	return NULL;
}

/**
 * @brief store TVO locally
 */
void save_tvo_locally(struct rpl_tvo_local_t * tvo_copy)
{
	uint8_t found_spot = 0;
	uint32_t temp_ts = UINT32_MAX;
	uint32_t i;
	uint32_t j = 0;

	for(i=0;i<TVO_LOCAL_BUFFER_LEN;i++){
		if(tvo_local_flags[i] == 0){
			found_spot = 1;
			//tvo_local_buffer[i] = tvo_copy;
			memcpy(&tvo_local_buffer[i], tvo_copy, sizeof(*tvo_copy));
			printf("blocking tvo buffer at %u for TVO (seq: %u)\n", (unsigned int)i, (unsigned int)(tvo_copy->tvo_seq));
			tvo_local_flags[i] = 1;
			break;
		}
		if(tvo_local_buffer[i].timestamp_received < temp_ts){
			temp_ts = tvo_local_buffer[i].timestamp_received;
			j = i;
		}
	}
	if(found_spot == 0){
		memcpy(&tvo_local_buffer[j], tvo_copy, sizeof(*tvo_copy));
		tvo_local_flags[j] = 1;
		printf("blocking tvo buffer at %u\n", (unsigned int)j);
		//tvo_local_buffer[j] = tvo_copy;
	}
}

/**
 * @brief reset TVO timer
 */
void reset_tvo_timer(void)
{
    ipv6_addr_t my_address;

    if ( get_my_ipv6_address(&my_address) != NULL ) {
        printf("**Node %u: Resetting all TRAIL parents -> accepting all incoming DIOs\n**",my_address.u8[15]);
    } else {
        printf("**Node (UNKNOWN): Resetting all TRAIL parents -> accepting all incoming DIOs\n**");
    }

	uint8_t i;
	for(i=0;i<RPL_MAX_PARENTS;i++){
		memset(&trail_parent_buffer[i], 0, sizeof(gnrc_rpl_dodag_trail_t));
	}
}

/**
 * @brief resend TVOs
 */
void resend_tvos(void)
{
	printf("\n   ########### CHECKING FOR TVO RESENDS ########\n\n");
	uint32_t i;

	uint8_t resend = 0;

	for(i=0;i<TVO_LOCAL_BUFFER_LEN;i++){
		if(tvo_local_flags[i] == 1){ //only resend for which no ack has been received
			resend++;
		//	printf("%u: ((%u - %u) > %u) && (%u < %u) --> %u \n",i, now.microseconds, tvo_local_buffer[i].timestamp_received, (DEFAULT_WAIT_FOR_TVO_ACK*1000000), tvo_local_buffer[i].number_resend, TVO_SEND_RETRIES, (now.microseconds - tvo_local_buffer[i].timestamp_received));
			if(((xtimer_now() - tvo_local_buffer[i].timestamp_received) > (DEFAULT_WAIT_FOR_TVO_ACK * SEC_IN_USEC)) && (tvo_local_buffer[i].number_resend < TVO_SEND_RETRIES)){
				//resend tvo
				struct rpl_tvo_t tvo;
				memcpy(&tvo, &tvo_local_buffer[i], sizeof(tvo));
			//	tvo.tvo_seq = tvo_local_buffer[i].his_tvo_seq;
				printf("*RE*");

				//test: send via multicast
	//			ipv6_addr_t next_hop;
//				memcpy(&next_hop, &(ipv6_buf->srcaddr), sizeof(next_hop));

			//	ipv6_addr_set_all_nodes_addr(&next_hop);
			//	send_TVO(&next_hop, &tvo, NULL);

				send_TVO(&tvo_local_buffer[i].dst_addr, &tvo, NULL);

				tvo_local_buffer[i].number_resend++;
				//usleep(500000);
                xtimer_usleep(250000);

			}
			if (tvo_local_buffer[i].number_resend >= TVO_SEND_RETRIES){
				printf("max number of resends reached: freeing tvo buffer at %u\n",(unsigned int)i);
				tvo_local_flags[i] = 0; //max number of resends, free buffer
				resend--;
			}
		}
	}
	if(resend == 0){
		delay_tvo(TEST_WAIT_FOR_TVO_ACK);
	}
//	else{
//		printf("Number of TVOs for resend at later point: %u\n",resend);
//	}
}

/**
 * @brief insert parent to TRAIL-parent buffer
 */
uint8_t include_parent_into_trail_buffer(void)
{
	for(size_t i=0;i<sizeof(trail_parent_buffer);i++){
		if(trail_parent_buffer[i].in_progress != 1){
			memset(&trail_parent_buffer[i], 0, sizeof(gnrc_rpl_dodag_trail_t));
			trail_parent_buffer[i].in_progress = 1;
			printf("Including parent into TRAIL buffer at %u\n",i);
			return i;
		}
	}
	return 255;
}

/**
 * @brief get a parent from the TRAIL-parent buffer
 */
uint8_t get_parent_from_trail_buffer(ipv6_addr_t *src_addr)
{
	uint8_t i;

	for(i=0;i<RPL_MAX_PARENTS;i++){
		if(trail_parent_buffer[i].parent_addr.u8[15] == src_addr->u8[15] && trail_parent_buffer[i].in_progress == 1){
			//printf("Returning parent from TRAIL buffer at %u\n",i);
			return i;
		}
	}
	//printf("Parent not in TRAIL buffer\n");
	return 255;
}

/**
 * @brief check if the parent is already verfied
 */
uint8_t is_parent_verified(ipv6_addr_t *src_addr, uint16_t dio_rank)
{
	gnrc_rpl_parent_t *parent;
	parent = rpl_find_parent(src_addr);

	if(parent == NULL){
		printf("Parent not yet in routing table - return false\n");
		return 0;
	}
	else if (parent->rank != dio_rank) {
		// TODO may have to delete parent first (?)
        gnrc_rpl_parent_remove(parent);
		printf("parent must have changed his rank - delete parent and return false\n");
		return 0;
	}
	else{
		printf("parent is in routing table with same rank - return true\n");
		return 1;
	}
}

/**
 * @brief send a TVO
 */
void send_TVO(ipv6_addr_t *destination, struct rpl_tvo_t *tvo, rpl_tvo_signature_t *signature)
{
    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    struct rpl_tvo_t *tvo_snd;
    rpl_tvo_signature_t *sig_snd;
    
    uint8_t size_signature = 0;
    int size = sizeof(icmpv6_hdr_t) + sizeof(*tvo_snd);
    if(signature != NULL && tvo->s_flag){
		size_signature = sizeof(*signature);
    }

    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, ICMP_CODE_TVO, size+size_signature)) == NULL) {
        DEBUG("RPL: Send TVO - no space left in packet buffer\n");
        return;
    }

    icmp = (icmpv6_hdr_t *)pkt->data;
    tvo_snd = (struct rpl_tvo_t *)(icmp + 1);
    sig_snd = (rpl_tvo_signature_t *)(tvo_snd + 1);
    
    memset(tvo_snd, 0, sizeof(*tvo_snd));
    memcpy(tvo_snd, tvo, sizeof(*tvo));
    if(size_signature > 0) {
        memcpy(sig_snd, signature, size_signature);
    }
    
    
    gnrc_rpl_instance_t *inst = _get_my_instance();
    gnrc_rpl_send(pkt, NULL, destination, (inst? &(inst->dodag.dodag_id) : NULL));
}

/**
 * @brief send a TVO-ACK
 */
void send_TVO_ACK(ipv6_addr_t *destination, uint8_t sequence_number)
{
    struct rpl_tvo_ack_t *tvo_ack;
    
    ipv6_addr_t my_address;
    if ( get_my_ipv6_address(&my_address) != NULL ) {
        printf("m: ID %u send msg TVO_ACK to ID %u #color3 - Seq. %u\n", my_address.u8[15],destination->u8[15], sequence_number);
    }
    else {
        printf("m: ID (UNKNOWN) send msg TVO_ACK to ID %u #color3 - Seq. %u\n", destination->u8[15], sequence_number);
    }
    
    //char addr_str[IPV6_MAX_ADDR_STR_LEN];
	//printf("send TVO-ACK (seq: %u) to %s (IPv6: ", sequence_number, ipv6_addr_to_str(addr_str, destination));
	//printf("send TVO-ACK to *ID %u* (seq: %u) (", destination->uint8[15], sequence_number);
    gnrc_rpl_instance_t *inst = _get_my_instance();
    
    if (inst == NULL) {
        return;
    }

    gnrc_pktsnip_t *pkt;
    icmpv6_hdr_t *icmp;
    int size = sizeof(icmpv6_hdr_t) + sizeof(*tvo_ack);
    if ((pkt = gnrc_icmpv6_build(NULL, ICMPV6_RPL_CTRL, ICMP_CODE_TVO_ACK, size)) == NULL) {
        DEBUG("RPL: Send TVO-ACK - no space left in packet buffer\n");
        return;
    }
   
    icmp = (icmpv6_hdr_t *)pkt->data;
    tvo_ack = (struct rpl_tvo_ack_t *)(icmp + 1);
    memset(tvo_ack, 0, sizeof(*tvo_ack));
    
    tvo_ack->rpl_instanceid = inst->id;
    tvo_ack->tvo_seq = sequence_number;
    tvo_ack->status = 0;

    gnrc_rpl_send(pkt, NULL, destination, (inst? &(inst->dodag.dodag_id) : NULL));
}

/**
 * @brief handle receive TVO
 */
void recv_rpl_tvo(struct rpl_tvo_t *tvo, ipv6_addr_t *srcaddr){
/*
	ipv6_addr_t ll_address;
	ipv6_addr_t my_address;
	ipv6_addr_set_link_local_prefix(&ll_address);
	ipv6_iface_get_best_src_addr(&my_address, &ll_address);

	ipv6_addr_t *next_hop;
	ipv6_buf = get_rpl_ipv6_buf();
	rpl_tvo_buf = get_rpl_tvo_buf();
*/

	//char addr_str[IPV6_MAX_ADDR_STR_LEN];
	//printf("received TVO (seq: %u) from %s (IPv6)\n", rpl_tvo_buf->tvo_seq, ipv6_addr_to_str(addr_str, &(ipv6_buf->srcaddr)));
	//printf("received TVO from *ID %u* (seq: %u)\n", ipv6_buf->srcaddr.uint8[15], rpl_tvo_buf->tvo_seq);
//	printf("m: ID %u received msg TVO(%u) from ID %u #color2\n", my_address.uint8[15], rpl_tvo_buf->tvo_seq, ipv6_buf->srcaddr.uint8[15]);

	//send_TVO_ACK(&(ipv6_buf->srcaddr), rpl_tvo_buf->tvo_seq);
    rpl_tvo_signature_t *signature = NULL;
    ipv6_addr_t my_address;
    ipv6_addr_t next_hop;

	memset(my_address.u8, 0, sizeof(&my_address));
	memset(next_hop.u8, 0, sizeof(&next_hop));

	if (tvo->s_flag) {
        signature = (rpl_tvo_signature_t*)(tvo+1);
    }

	 struct rpl_tvo_local_t *local_tvo = has_tvo_been_received(srcaddr, tvo->tvo_seq);


	 if(local_tvo != NULL) // already received
	 {
		 /**
		  * refactor: eigentlich wird nur tvo_seq benötigt. Zweiten array mit addr_suffix und seq number
		  * suche nach tupel
		  * sende ack oder sonst speicher zum forwarden
		  * --> tvo struct muss nur zum forwarden gespeichert werden
		  * --> zum acken könnten so wesentlich mehr vorenthalten werden
		  * --> acken und forwarden wäre entkoppelt -> "löschen, da ack erhalten" hat dann nichts mehr mit
		  *  "sollte die TVO noch acken" zu tun.
		  */
		// printf("\n Already received TVO (seq: %u) from %s\n", rpl_tvo_buf->tvo_seq, ipv6_addr_to_str(addr_str, &(ipv6_buf->srcaddr)));
        if ( get_my_ipv6_address(&my_address) != NULL ) {
            printf("m: ID %u received msg TVO from ID %u #color10 - Seq. %u\n", my_address.u8[15], srcaddr->u8[15], tvo->tvo_seq);
        }
        else {
            printf("m: ID (UNKNOWN) received msg TVO from ID %u #color10 - Seq. %u\n", srcaddr->u8[15], tvo->tvo_seq);
        }
		 
		 send_TVO_ACK(srcaddr, tvo->tvo_seq);
		 return;
	 }

	gnrc_rpl_dodag_t *my_dodag = NULL;

	if(tvo->s_flag){ //response

		printf("m: ID %u received msg TVO from ID %u #color9 - Seq. %u\n", my_address.u8[15], srcaddr->u8[15], tvo->tvo_seq);

		if(memcmp(tvo->src_addr.u8, &my_address.u8, sizeof(my_address.u8))){

			//am I the source?
			printf("*TVO origin* checking signature ... ");

			uint8_t trail_index;
			trail_index = get_parent_from_trail_buffer(srcaddr);
			if(trail_index == 255){
				printf("parent is not in list -> already verified... \n");
				send_TVO_ACK(srcaddr, tvo->tvo_seq);
				return;
			}

			if(signature->uint8[0] != 0){ //TODO any signature-dummy is OK
				printf("**valid**\n");


                // lets join the DODAG/Instance
                gnrc_rpl_instance_t *inst = NULL;
                gnrc_rpl_dodag_t *dodag = NULL;
                
                if (gnrc_rpl_instance_add(trail_parent_buffer[trail_index].instance_id, &inst)) {
                    
                    puts("Ohoh, we have no instance yet, this one will be tricky!");
                    // new instance
                    //inst->mop = (dio->g_mop_prf >> GNRC_RPL_MOP_SHIFT) & GNRC_RPL_SHIFTED_MOP_MASK;
                    //inst->of = gnrc_rpl_get_of_for_ocp(GNRC_RPL_DEFAULT_OCP);
                    //gnrc_rpl_dodag_init(inst, &dio->dodag_id);
                    
                }
                else {
                    
                    if (inst == NULL) {
                        puts("ERROR: no space left to create a new RPL Instance for TRAIL!");
                        return;
                    }
                    // if inst != NULL we have this instance already
                    dodag = &inst->dodag;
                    //memcpy(&dodag, &trail_parent_buffer[trail_index], sizeof(*dodag));
                    my_dodag = rpl_get_my_dodag();
                    
                    if (my_dodag != NULL && ipv6_addr_equal(&my_dodag->dodag_id, &dodag->dodag_id)) {
                        
                        if(my_dodag->my_rank <= trail_parent_buffer[trail_index].parent_rank){
                            printf("IGNORING TVO DUE TO RANK: my rank %u , parent rank %u\n", my_dodag->my_rank, trail_parent_buffer[trail_index].parent_rank);
                            trail_parent_buffer[trail_index].in_progress = 0; // free buffer
                            send_TVO_ACK(srcaddr, tvo->tvo_seq);
                            return;
                        }
                        
                        // we check the conditions of the DODAG
                        if (GNRC_RPL_COUNTER_GREATER_THAN(dodag->version, my_dodag->version)) {
                            if (my_dodag->node_status == GNRC_RPL_ROOT_NODE) {
                                my_dodag->version = GNRC_RPL_COUNTER_INCREMENT(dodag->version);
                                trickle_reset_timer(&my_dodag->trickle);
                            }
                            else {
                                my_dodag->version = dodag->version;
                                gnrc_rpl_local_repair(my_dodag);
                            }
                        }
                        else if (GNRC_RPL_COUNTER_GREATER_THAN(my_dodag->version, dodag->version)) {
                            trickle_reset_timer(&my_dodag->trickle);
                            return;
                        }
                        
                        // its my DODAG and the parent rank is lower -> we add this parent
                        gnrc_rpl_parent_t *parent = NULL;

                        if (!gnrc_rpl_parent_add_by_addr(dodag, &trail_parent_buffer[trail_index].parent_addr, &parent) && (parent == NULL)) {
                            DEBUG("RPL: Could not allocate new parent TRAIL.\n");
                            gnrc_rpl_instance_remove(inst);
                            return;
                        }
                        parent->rank = trail_parent_buffer[trail_index].parent_rank;
                        gnrc_rpl_parent_update(dodag, parent);
                        
                        trail_parent_buffer[trail_index].in_progress = 0; // free buffer
                        send_TVO_ACK(srcaddr, tvo->tvo_seq);
                        return;
                    }
                    // END is valid
                }
				return;
			}
			else{
				printf(" **invalid**\n");
			//	trail_parent_buffer[trail_index].verified = 0; // not verfied
			//	trail_parent_buffer[trail_index].pending = 0;
				trail_parent_buffer[trail_index].in_progress = 0; //free buffer

				send_TVO_ACK(srcaddr, tvo->tvo_seq);
				return;
			}
		}
		else{
			/*
			 * Received tvo on way back
			 */
            kernel_pid_t iface_id = KERNEL_PID_UNDEF;
            size_t next_hop_size = sizeof(ipv6_addr_t);
            uint32_t next_hop_flags = 0;
            
            fib_get_next_hop(&gnrc_ipv6_fib_table, &iface_id,
                     next_hop.u8, &next_hop_size,
                     &next_hop_flags, tvo->src_addr.u8, sizeof(ipv6_addr_t), 0);
		}
	}
	else{
		/*
		 * received tvo on way to root
		 */
		printf("m: ID %u received msg TVO from ID %u #color8 - Seq. %u\n", my_address.u8[15], srcaddr->u8[15], tvo->tvo_seq);
        my_dodag = rpl_get_my_dodag();
		//TVO is a request: on the way to the root
		if(my_dodag == NULL){
			printf("** Not in network, yet - dropping TVO **\n");
			//send_TVO_ACK(&(ipv6_buf->srcaddr), rpl_tvo_buf->tvo_seq);
			return;
		}
		//am I tested? (rank == 0)
		else if(tvo->rank == 0){
			printf("Include rank (%u) into TVO \n", my_dodag->my_rank);
			// tested: set to my rank
			tvo->rank = my_dodag->my_rank;
		}
		// not tested -> is rank OK?
		else if(tvo->rank <= my_dodag->my_rank) {
			// not OK -> DROP
			printf("** TVO contains invalid rank: %u **\n", tvo->rank);
			send_TVO_ACK(srcaddr, tvo->tvo_seq);
			return;
		}

		// delete first in case a better entry is available
       // fib_remove_entry(&gnrc_ipv6_fib_table, &tvo->src_addr, sizeof(ipv6_addr_t));
       // fib_remove_entry(&gnrc_ipv6_fib_table, &ipv6_buf->srcaddr, sizeof(ipv6_addr_t));

            ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
            kernel_pid_t if_id;
            if ((if_id = gnrc_ipv6_netif_find_by_addr(NULL, &all_RPL_nodes)) != KERNEL_PID_UNDEF) {
                
                //add downward routing entry to send TVO back to source
                fib_add_entry(&gnrc_ipv6_fib_table, if_id, tvo->src_addr.u8, sizeof(ipv6_addr_t),
                              (0x0),
                              srcaddr->u8, sizeof(ipv6_addr_t), FIB_FLAG_RPL_ROUTE,
                              (my_dodag->default_lifetime * my_dodag->lifetime_unit) * SEC_IN_MS);
                
                //add downward routing entry for next hop (one-hop neighbor)
                fib_add_entry(&gnrc_ipv6_fib_table, if_id, srcaddr->u8, sizeof(ipv6_addr_t),
                              (0x0),
                              srcaddr->u8, sizeof(ipv6_addr_t), FIB_FLAG_RPL_ROUTE,
                              (my_dodag->default_lifetime * my_dodag->lifetime_unit) * SEC_IN_MS);
            }

		//add downward routing entry to send TVO back to source
		//rpl_add_routing_entry(&rpl_tvo_buf->src_addr, &ipv6_buf->srcaddr, 1000);
		//add downward routing entry for next hop (one-hop neighbor)
		//rpl_add_routing_entry(&ipv6_buf->srcaddr, &ipv6_buf->srcaddr, 1000);

		//rank OK, NOT tested -> continue
		// am I root?
		if(my_dodag->my_rank == GNRC_RPL_ROOT_RANK){
			//rpl_tvo_signature_buf = get_tvo_signature_buf(TVO_BASE_LEN);
			//memset(rpl_tvo_signature_buf, 0, sizeof(*rpl_tvo_signature_buf));
            rpl_tvo_signature_t sig_mem;
            memset(&sig_mem, 0, sizeof(rpl_tvo_signature_t));
            signature = &sig_mem;
            printf("Signing TVO ... ");
			signature->uint8[0] = 0xab;//123;
			printf("done\n");

			tvo->s_flag = 1;
			//next_hop = rpl_get_next_hop(&rpl_tvo_buf->src_addr);
            
            
            kernel_pid_t iface_id = KERNEL_PID_UNDEF;
            size_t next_hop_size = sizeof(ipv6_addr_t);
            uint32_t next_hop_flags = 0;

            fib_get_next_hop(&gnrc_ipv6_fib_table, &iface_id,
                     next_hop.u8, &next_hop_size,
                     &next_hop_flags, tvo->src_addr.u8, sizeof(ipv6_addr_t), 0);
		}
		else{
			//not root: forward to preferred parent
			//next_hop = &my_dodag->my_preferred_parent->addr;
            
            kernel_pid_t iface_id = KERNEL_PID_UNDEF;
            size_t next_hop_size = sizeof(ipv6_addr_t);
            uint32_t next_hop_flags = 0;
            
            fib_get_next_hop(&gnrc_ipv6_fib_table, &iface_id,
                     next_hop.u8, &next_hop_size, &next_hop_flags, 
                     my_dodag->parents->addr.u8, sizeof(ipv6_addr_t), 0);
            
		}
	}

	tvo_sequence_number++;
	struct rpl_tvo_local_t tvo_inst;
	local_tvo = &tvo_inst;
	// copy tvo to local_tvo
	memset(local_tvo, 0, sizeof(*local_tvo));
	memcpy(local_tvo, tvo, sizeof(*tvo));
	// assign his_counter (tvo.seqnr) to local tvo.his_seq_num
	local_tvo->his_tvo_seq = local_tvo->tvo_seq;
	local_tvo->number_resend = 0;
	// assign tvo_seq_number to local tvo Seq number
	local_tvo->tvo_seq = tvo_sequence_number;
	tvo->tvo_seq = tvo_sequence_number;
	// give local tvo a timestamp
	//timex_t now;
	//vtimer_now(&now);
	local_tvo->timestamp_received = xtimer_now();//now.microseconds;
	//save destination / source
	local_tvo->prev_hop_addr = *srcaddr;

	memcpy(&(local_tvo->dst_addr), next_hop.u8, sizeof(local_tvo->dst_addr));
	// save_tvo_locally(local_tvo);
	save_tvo_locally(local_tvo);
	// send ack?

	send_TVO_ACK(srcaddr, local_tvo->his_tvo_seq);
	send_TVO(&next_hop, tvo, signature);
	delay_tvo(DEFAULT_WAIT_FOR_TVO_ACK);
}


void recv_rpl_tvo_ack(struct rpl_tvo_ack_t* tvo_ack, ipv6_addr_t *srcaddr)
{

    //rpl_dodag_t *my_dodag = rpl_get_my_dodag();

   // ipv6_buf = get_rpl_ipv6_buf();
   // rpl_tvo_ack_buf = get_rpl_tvo_ack_buf();

   // char addr_str[IPV6_MAX_ADDR_STR_LEN];
    //printf("*** received TVO-ACK (seq: %u) from %s\n", rpl_tvo_ack_buf->tvo_seq ,ipv6_addr_to_str(addr_str, &(ipv6_buf->srcaddr)));
   // printf("*** received TVO-ACK from *ID %u* (seq: %u)\n", ipv6_buf->srcaddr.uint8[15], rpl_tvo_ack_buf->tvo_seq);
   ipv6_addr_t my_address;
    if ( get_my_ipv6_address(&my_address) != NULL ) {
        printf("m: ID %u received msg TVO_ACK from ID %u #color11 - Seq. %u\n", my_address.u8[15],  srcaddr->u8[15], tvo_ack->tvo_seq);
    }
    else {
        printf("m: ID (UNKNOWN) received msg TVO_ACK from ID %u #color11 - Seq. %u\n", srcaddr->u8[15], tvo_ack->tvo_seq);
    }

    if (tvo_ack->status != 0) {
        return;
    }

  //  received_tvo_ack();
    tvo_ack_has_been_received(srcaddr, tvo_ack->tvo_seq);
}










kernel_pid_t gnrc_rpl_init(kernel_pid_t if_pid)
{
    /* check if RPL was initialized before */
    if (gnrc_rpl_pid == KERNEL_PID_UNDEF) {
        _instance_id = 0;
        /* start the event loop */
        gnrc_rpl_pid = thread_create(_stack, sizeof(_stack), GNRC_RPL_PRIO,
                                     THREAD_CREATE_STACKTEST,
                                     _event_loop, NULL, "RPL");

        if (gnrc_rpl_pid == KERNEL_PID_UNDEF) {
            DEBUG("RPL: could not start the event loop\n");
            return KERNEL_PID_UNDEF;
        }

        _me_reg.demux_ctx = ICMPV6_RPL_CTRL;
        _me_reg.pid = gnrc_rpl_pid;
        /* register interest in all ICMPv6 packets */
        gnrc_netreg_register(GNRC_NETTYPE_ICMPV6, &_me_reg);

        gnrc_rpl_of_manager_init();
        xtimer_set_msg(&_lt_timer, _lt_time, &_lt_msg, gnrc_rpl_pid);
    }

    /* register all_RPL_nodes multicast address */
    ipv6_addr_t all_RPL_nodes = GNRC_RPL_ALL_NODES_ADDR;
    gnrc_ipv6_netif_add_addr(if_pid, &all_RPL_nodes, IPV6_ADDR_BIT_LEN, 0);

    gnrc_rpl_send_DIS(NULL, &all_RPL_nodes);
    
    tvo_delay_over_pid = thread_create(tvo_delay_over_buf, TVO_DELAY_STACKSIZE,
                                       (THREAD_PRIORITY_MAIN-1), THREAD_CREATE_STACKTEST,
                                       tvo_delay_over, NULL, "tvo_delay_over");
    return gnrc_rpl_pid;
}

gnrc_rpl_instance_t *gnrc_rpl_root_init(uint8_t instance_id, ipv6_addr_t *dodag_id,
                                        bool gen_inst_id, bool local_inst_id)
{
    if (gen_inst_id) {
        instance_id = gnrc_rpl_gen_instance_id(local_inst_id);
    }

    gnrc_rpl_dodag_t *dodag = NULL;
    gnrc_rpl_instance_t *inst = gnrc_rpl_root_instance_init(instance_id, dodag_id,
                                                         GNRC_RPL_DEFAULT_MOP);

    if (!inst) {
        return NULL;
    }

    dodag = &inst->dodag;

    dodag->dtsn = 1;
    dodag->prf = 0;
    dodag->dio_interval_doubl = GNRC_RPL_DEFAULT_DIO_INTERVAL_DOUBLINGS;
    dodag->dio_min = GNRC_RPL_DEFAULT_DIO_INTERVAL_MIN;
    dodag->dio_redun = GNRC_RPL_DEFAULT_DIO_REDUNDANCY_CONSTANT;
    dodag->default_lifetime = GNRC_RPL_DEFAULT_LIFETIME;
    dodag->lifetime_unit = GNRC_RPL_LIFETIME_UNIT;
    dodag->version = GNRC_RPL_COUNTER_INIT;
    dodag->grounded = GNRC_RPL_GROUNDED;
    dodag->node_status = GNRC_RPL_ROOT_NODE;
    dodag->my_rank = GNRC_RPL_ROOT_RANK;
    dodag->dodag_conf_requested = true;
    dodag->prefix_info_requested = true;

    trickle_start(gnrc_rpl_pid, &dodag->trickle, GNRC_RPL_MSG_TYPE_TRICKLE_INTERVAL,
                  GNRC_RPL_MSG_TYPE_TRICKLE_CALLBACK, (1 << dodag->dio_min),
                  dodag->dio_interval_doubl, dodag->dio_redun);

    return inst;
}

static void _receive(gnrc_pktsnip_t *icmpv6)
{
    gnrc_pktsnip_t *ipv6 = NULL;
    ipv6_hdr_t *ipv6_hdr = NULL;
    icmpv6_hdr_t *icmpv6_hdr = NULL;

    LL_SEARCH_SCALAR(icmpv6, ipv6, type, GNRC_NETTYPE_IPV6);

    assert(ipv6 != NULL);

    ipv6_hdr = (ipv6_hdr_t *)ipv6->data;

    icmpv6_hdr = (icmpv6_hdr_t *)icmpv6->data;
    switch (icmpv6_hdr->code) {
        case GNRC_RPL_ICMPV6_CODE_DIS:
            DEBUG("RPL: DIS received\n");
            gnrc_rpl_recv_DIS((gnrc_rpl_dis_t *)(icmpv6_hdr + 1), &ipv6_hdr->src, &ipv6_hdr->dst,
                    byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DIO:
            DEBUG("RPL: DIO received\n");
            gnrc_rpl_recv_DIO((gnrc_rpl_dio_t *)(icmpv6_hdr + 1), &ipv6_hdr->src,
                    byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO:
            DEBUG("RPL: DAO received\n");
            gnrc_rpl_recv_DAO((gnrc_rpl_dao_t *)(icmpv6_hdr + 1), &ipv6_hdr->src,
                    byteorder_ntohs(ipv6_hdr->len));
            break;
        case GNRC_RPL_ICMPV6_CODE_DAO_ACK:
            DEBUG("RPL: DAO-ACK received\n");
            gnrc_rpl_recv_DAO_ACK((gnrc_rpl_dao_ack_t *)(icmpv6_hdr + 1),
                    byteorder_ntohs(ipv6_hdr->len));
            break;
        case (ICMP_CODE_TVO): {puts("ICMP TVO");
					recv_rpl_tvo((struct rpl_tvo_t *)(icmpv6_hdr + 1),
					&ipv6_hdr->src);
					break;
				 }

		case (ICMP_CODE_TVO_ACK): {puts("ICMP TVO_ACK");
			recv_rpl_tvo_ack((struct rpl_tvo_ack_t *)(icmpv6_hdr + 1),
					&ipv6_hdr->src);
			
			break;
		 }
        default:
            DEBUG("RPL: Unknown ICMPV6 code received\n");
            break;
    }

    gnrc_pktbuf_release(icmpv6);
}

static void *_event_loop(void *args)
{
    msg_t msg, reply;

    (void)args;
    msg_init_queue(_msg_q, GNRC_RPL_MSG_QUEUE_SIZE);

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    trickle_t *trickle;
    /* start event loop */
    while (1) {
        DEBUG("RPL: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE:
                DEBUG("RPL: GNRC_RPL_MSG_TYPE_LIFETIME_UPDATE received\n");
                _update_lifetime();
                break;
            case GNRC_RPL_MSG_TYPE_TRICKLE_INTERVAL:
                DEBUG("RPL: GNRC_RPL_MSG_TYPE_TRICKLE_INTERVAL received\n");
                trickle = (trickle_t *) msg.content.ptr;
                if (trickle && (trickle->callback.func != NULL)) {
                    trickle_interval(trickle);
                }
                break;
            case GNRC_RPL_MSG_TYPE_TRICKLE_CALLBACK:
                DEBUG("RPL: GNRC_RPL_MSG_TYPE_TRICKLE_CALLBACK received\n");
                trickle = (trickle_t *) msg.content.ptr;
                if (trickle && (trickle->callback.func != NULL)) {
                    trickle_callback(trickle);
                }
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("RPL: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                _receive((gnrc_pktsnip_t *)msg.content.ptr);
                break;
            case GNRC_NETAPI_MSG_TYPE_SND:
                break;
            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                DEBUG("RPL: reply to unsupported get/set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }
    }

    return NULL;
}

void _update_lifetime(void)
{
    uint32_t now = xtimer_now();
    uint16_t now_sec = now / SEC_IN_USEC;

    gnrc_rpl_parent_t *parent;
    gnrc_rpl_instance_t *inst;

    for (uint8_t i = 0; i < GNRC_RPL_PARENTS_NUMOF; ++i) {
        parent = &gnrc_rpl_parents[i];
        if (parent->state != 0) {
            if ((int32_t)(parent->lifetime - now_sec) <= GNRC_RPL_LIFETIME_UPDATE_STEP) {
                gnrc_rpl_dodag_t *dodag = parent->dodag;
                gnrc_rpl_parent_remove(parent);
                gnrc_rpl_parent_update(dodag, NULL);
                continue;
            }
            else if ((int32_t)(parent->lifetime - now_sec) <= (GNRC_RPL_LIFETIME_UPDATE_STEP * 2)) {
                gnrc_rpl_send_DIS(parent->dodag->instance, &parent->addr);
            }
        }
    }

    for (int i = 0; i < GNRC_RPL_INSTANCES_NUMOF; ++i) {
        inst = &gnrc_rpl_instances[i];
        if (inst->state != 0) {
            if ((inst->cleanup > 0) && (inst->dodag.parents == NULL) &&
                (inst->dodag.my_rank == GNRC_RPL_INFINITE_RANK)) {
                inst->cleanup -= GNRC_RPL_LIFETIME_UPDATE_STEP;
                if (inst->cleanup <= 0) {
                    /* no parents - delete this instance and DODAG */
                    gnrc_rpl_instance_remove(inst);
                    continue;
                }
            }

            if (inst->dodag.dao_time > GNRC_RPL_LIFETIME_UPDATE_STEP) {
                inst->dodag.dao_time -= GNRC_RPL_LIFETIME_UPDATE_STEP;
            }
            else {
                _dao_handle_send(&inst->dodag);
            }
        }
    }

    xtimer_set_msg(&_lt_timer, _lt_time, &_lt_msg, gnrc_rpl_pid);
}

void gnrc_rpl_delay_dao(gnrc_rpl_dodag_t *dodag)
{
    dodag->dao_time = GNRC_RPL_DEFAULT_DAO_DELAY;
    dodag->dao_counter = 0;
    dodag->dao_ack_received = false;
}

void gnrc_rpl_long_delay_dao(gnrc_rpl_dodag_t *dodag)
{
    dodag->dao_time = GNRC_RPL_REGULAR_DAO_INTERVAL;
    dodag->dao_counter = 0;
    dodag->dao_ack_received = false;
}

void _dao_handle_send(gnrc_rpl_dodag_t *dodag)
{
    if ((dodag->dao_ack_received == false) && (dodag->dao_counter < GNRC_RPL_DAO_SEND_RETRIES)) {
        dodag->dao_counter++;
        gnrc_rpl_send_DAO(dodag->instance, NULL, dodag->default_lifetime);
        dodag->dao_time = GNRC_RPL_DEFAULT_WAIT_FOR_DAO_ACK;
    }
    else if (dodag->dao_ack_received == false) {
        gnrc_rpl_long_delay_dao(dodag);
    }
}

uint8_t gnrc_rpl_gen_instance_id(bool local)
{
    mutex_lock(&_inst_id_mutex);
    uint8_t instance_id = GNRC_RPL_DEFAULT_INSTANCE;

    if (local) {
        instance_id = ((_instance_id++) | GNRC_RPL_INSTANCE_ID_MSB);
        mutex_unlock(&_inst_id_mutex);
        return instance_id;
    }

    instance_id = ((_instance_id++) & GNRC_RPL_GLOBAL_INSTANCE_MASK);
    mutex_unlock(&_inst_id_mutex);
    return instance_id;
}

/**
 * @}
 */
