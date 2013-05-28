/******************************************************************************
 * V4V
 *
 * Version 2 of v2v (Virtual-to-Virtual)
 *
 * Copyright (c) 2010, Citrix Systems
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __XEN_PUBLIC_V4V_H__
#define __XEN_PUBLIC_V4V_H__

#include "xen.h"
#include "event_channel.h"

/*
 * Structure definitions
 */

#define V4V_RING_MAGIC          0xa822f72bb0b9d8ccUL
#define V4V_RING_DATA_MAGIC     0x45fe852220b801d4UL

#define V4V_MESSAGE_DGRAM       0x3c2c1db8
#define V4V_MESSAGE_STREAM      0x70f6a8e5

#define V4V_DOMID_ANY           DOMID_INVALID
#define V4V_PORT_ANY            0

typedef uint64_t v4v_pfn_t;

typedef struct v4v_iov
{
    uint64_t iov_base;
    uint32_t iov_len;
    uint32_t pad;
} v4v_iov_t;

typedef struct v4v_addr
{
    uint32_t port;
    domid_t domain;
    uint16_t pad;
} v4v_addr_t;

typedef struct v4v_ring_id
{
    v4v_addr_t addr;
    domid_t partner;
    uint16_t pad;
} v4v_ring_id_t;

typedef struct v4v_send_addr
{
    v4v_addr_t src;
    v4v_addr_t dst;
} v4v_send_addr_t;

/*
 * v4v_ring
 * id: xen only looks at this during register/unregister
 *     and will fill in id.addr.domain
 * rx_ptr: rx pointer, modified by domain
 * tx_ptr: tx pointer, modified by xen
 *
 */
typedef struct v4v_ring
{
    uint64_t magic;
    v4v_ring_id_t id;
    uint32_t len;
    uint32_t rx_ptr;
    uint32_t tx_ptr;
    uint8_t reserved[32];
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t ring[];
#elif defined(__GNUC__)
    uint8_t ring[0];
#endif
} v4v_ring_t;

#define V4V_RING_DATA_F_EMPTY       (1U << 0) /* Ring is empty */
#define V4V_RING_DATA_F_EXISTS      (1U << 1) /* Ring exists */
#define V4V_RING_DATA_F_PENDING     (1U << 2) /* Pending interrupt exists - do
                                               * not rely on this field - for
                                               * profiling only */
#define V4V_RING_DATA_F_SUFFICIENT  (1U << 3) /* Sufficient space to queue
                                               * space_required bytes exists */

typedef struct v4v_ring_data_ent
{
    v4v_addr_t ring;
    uint16_t flags;
    uint16_t pad;
    uint32_t space_required;
    uint32_t max_message_size;
} v4v_ring_data_ent_t;

typedef struct v4v_ring_data
{
    uint64_t magic;
    uint32_t nent;
    uint32_t pad;
    uint64_t reserved[4];
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    v4v_ring_data_ent_t data[];
#elif defined(__GNUC__)
    v4v_ring_data_ent_t data[0];
#endif
} v4v_ring_data_t;

typedef struct v4v_info
{
    uint64_t ring_magic;
    uint64_t data_magic;
    evtchn_port_t evtchn;
    uint32_t max_rings;
    uint32_t max_sendv;
    uint32_t max_notify;
    uint32_t max_send_size;
    uint32_t pad;
} v4v_info_t;

#define V4V_DEFAULT_MAX_RINGS      0x80  /* Default 128 rings */
#define V4V_DEFAULT_MAX_SENDV      0x80  /* Default 128 vectors */
#define V4V_DEFAULT_MAX_NOTIFY     0x100 /* Default 256 notify requests */
#define V4V_DEFAULT_MAX_SEND_SIZE  0x2000000  /* Default 32Mb per send */

typedef struct v4v_config
{
    uint32_t max_rings;
    uint32_t max_sendv;
    uint32_t max_notify;
    uint32_t max_send_size;
    domid_t target_id;
    uint16_t pad;
} v4v_config_t;

#define V4V_SHF_SYN            (1 << 0)
#define V4V_SHF_ACK            (1 << 1)
#define V4V_SHF_RST            (1 << 2)

#define V4V_SHF_PING           (1 << 8)
#define V4V_SHF_PONG           (1 << 9)

struct v4v_stream_header
{
    uint32_t flags;
    uint32_t conid;
};

struct v4v_ring_message_header
{
    uint32_t len;
    uint32_t message_type;
    v4v_addr_t source;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t data[];
#elif defined(__GNUC__)
    uint8_t data[0];
#endif
};

typedef struct v4vtables_rule
{
    v4v_addr_t src;
    v4v_addr_t dst;
    uint32_t accept;
} v4vtables_rule_t;

typedef struct v4vtables_list
{
    uint32_t start_rule;
    uint32_t nb_rules;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    struct v4vtables_rule rules[];
#elif defined(__GNUC__)
    struct v4vtables_rule rules[0];
#endif
} v4vtables_list_t;

/*
 * HYPERCALLS
 */

/*
 * V4VOP_register_ring
 *
 * Registers a ring with Xen. If a ring with the same v4v_ring_id exists,
 * the hypercall will return -EEXIST.
 *
 * do_v4v_op(V4VOP_register_ring,
 *           XEN_GUEST_HANDLE(v4v_ring_t),
 *           XEN_GUEST_HANDLE(v4v_pfn_t),
 *           uint32_t npage,
 *           0)
 */
#define V4VOP_register_ring    1

/*
 * V4VOP_unregister_ring
 *
 * Unregister a ring.
 *
 * do_v4v_op(V4VOP_unregister_ring,
 *           XEN_GUEST_HANDLE(v4v_ring_t),
 *           NULL, 0, 0)
 */
#define V4VOP_unregister_ring  2

/*
 * V4VOP_notify
 *
 * Asks xen for information about other rings in the system.
 *
 * ent->ring is the v4v_addr_t of the ring you want information on
 * the same matching rules are used as for V4VOP_send.
 *
 * ent->space_required  if this field is not null xen will check
 * that there is space in the destination ring for this many bytes
 * of payload. If there is it will set the V4V_RING_DATA_F_SUFFICIENT
 * and CANCEL any pending interrupt for that ent->ring, if insufficient
 * space is available it will schedule an interrupt and the flag will
 * not be set.
 *
 * The flags are set by xen when notify replies
 * V4V_RING_DATA_F_EMPTY        ring is empty
 * V4V_RING_DATA_F_PENDING      interrupt is pending - don't rely on this
 * V4V_RING_DATA_F_SUFFICIENT   sufficient space for space_required is there
 * V4V_RING_DATA_F_EXISTS       ring exists
 *
 * do_v4v_op(V4VOP_notify,
 *           XEN_GUEST_HANDLE(v4v_ring_data_t) ring_data,
 *           NULL, 0, 0)
 */
#define V4VOP_notify           4

/*
 * V4VOP_sendv
 *
 * Sends of list of buffer contained in iov.
 *
 * For each iov entry send iov_len bytes of iov_base to addr.dst, giving
 * src as the source address (xen will ignore src->domain and put your
 * domain in the actual message), xen first looks for a ring with id.addr==dst
 * and id.partner==sending_domain if that fails it looks for id.addr==dst and
 * id.partner==DOMID_ANY.
 *
 * The message_type is the 32 bit number used from the message most likely
 * V4V_MESSAGE_DGRAM or V4V_MESSAGE_STREAM. If insufficient space exists
 * it will return -EAGAIN and xen will send an interrupt on the appropriate
 * event channel when sufficient space becomes available.
 *
 * do_v4v_op(V4VOP_sendv,
 *           XEN_GUEST_HANDLE(v4v_send_addr_t) addr,
 *           XEN_GUEST_HANDLE(v4v_iov_t) iov,
 *           uint32_t niov,
 *           uint32_t message_type)
 */
#define V4VOP_sendv            5

/*
 * V4VOP_info
 *
 * Returns v4v info for the current domain (domain that issued the hypercall).
 *      - V4V magic number
 *      - event channel port (for current domain)
 *      - four current V4V configuration settings
 *
 * do_v4v_op(V4VOP_info,
 *           XEN_GUEST_HANDLE(v4v_info_t) info,
 *           NULL, 0, 0)
 */
#define V4VOP_info             6

/*
 * V4VOP_config
 *
 * Allows internal configuration settings to be adjusted for a recently
 * created domain specified by target_id. If not called the V4V_DEFAULT_*
 * values will be used internally.
 *
 * do_v4v_op(V4VOP_config,
 *           XEN_GUEST_HANDLE(v4v_config_t) config,
 *           NULL, 0, 0)
 */
#define V4VOP_config           7

/*
 * V4VOP_tables_add
 *
 * Insert a filtering rules after a given position.
 *
 * do_v4v_op(V4VOP_tables_add,
 *           XEN_GUEST_HANDLE(v4vtables_rule_t) rule,
 *           NULL,
 *           uint32_t position, 0)
 */
#define V4VOP_tables_add       8

/*
 * V4VOP_tables_del
 *
 * Delete a filtering rules at a position or the rule
 * that matches "rule".
 *
 * do_v4v_op(V4VOP_tables_del,
 *           XEN_GUEST_HANDLE(v4vtables_rule_t) rule,
 *           NULL,
 *           uint32_t position, 0)
 */
#define V4VOP_tables_del       9

/*
 * V4VOP_tables_list
 *
 * do_v4v_op(V4VOP_tables_list,
 *           XEN_GUEST_HANDLE(v4vtpables_list_t) list,
 *           NULL, 0, 0)
 */
#define V4VOP_tables_list      10

#endif /* __XEN_PUBLIC_V4V_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
