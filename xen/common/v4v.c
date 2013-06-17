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

#include <xen/config.h>
#include <xen/mm.h>
#include <xen/compat.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/v4v.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/keyhandler.h>
#include <asm/types.h>

DEFINE_XEN_GUEST_HANDLE(v4v_iov_t);
DEFINE_XEN_GUEST_HANDLE(v4v_addr_t);
DEFINE_XEN_GUEST_HANDLE(v4v_send_addr_t);
DEFINE_XEN_GUEST_HANDLE(v4v_ring_t);
DEFINE_XEN_GUEST_HANDLE(v4v_ring_data_ent_t);
DEFINE_XEN_GUEST_HANDLE(v4v_ring_data_t);
DEFINE_XEN_GUEST_HANDLE(v4v_info_t);
DEFINE_XEN_GUEST_HANDLE(v4v_config_t);
DEFINE_XEN_GUEST_HANDLE(v4v_pfn_t);
DEFINE_XEN_GUEST_HANDLE(v4vtables_rule_t);
DEFINE_XEN_GUEST_HANDLE(v4vtables_list_t);
DEFINE_XEN_GUEST_HANDLE(uint8_t);

struct v4v_pending_ent
{
    struct hlist_node node;
    domid_t id;
    uint32_t len;
};

struct v4vtables_rule_node
{
    struct list_head list;
    v4vtables_rule_t rule;
};

/* FIXME: refactor ring_info into 2 parts, to remove the need for
   the ring_id and the hash/pending information */
struct v4v_ring_info
{
    /* next node in the hash, protected by L2  */
    struct hlist_node node;
    /* this ring's id, protected by L2 */
    v4v_ring_id_t id;
    /* L3 */
    spinlock_t lock;
    /* cached length of the ring (from ring->len), protected by L3 */
    uint32_t len;
    uint32_t npage;
    /* cached tx pointer location, protected by L3 */
    uint32_t tx_ptr;
    /* mapped ring pages protected by L3*/
    uint8_t **mfn_mapping;
    /* list of mfns of guest ring */
    mfn_t *mfns;
    /* list of struct v4v_pending_ent for this ring, L3 */
    struct hlist_head pending;
};

/*
 * The value of the v4v element in a struct domain is
 * protected by the global lock L1
 */
#define V4V_HTABLE_SIZE 32
struct v4v_domain
{
    /* L2 */
    rwlock_t lock;
    /* event channel */
    evtchn_port_t evtchn_port;
    /* configuration values for this v4v object */
    uint32_t max_rings;
    uint32_t max_sendv;
    uint32_t max_notify;
    uint32_t max_send_size;
    /* current ring count for this domain */
    uint32_t ring_count;
    /* protected by L2 */
    struct v4v_ring_info *ring_notification;
    struct v4v_ring_info *ring_listen;
    struct hlist_head ring_hash[V4V_HTABLE_SIZE];
};

/*
 * Messages on the ring are padded to 128 bits
 * Len here refers to the exact length of the data not including the
 * 128 bit header. The message uses
 * ((len + 0xf) & ~0xf) + sizeof(v4v_ring_message_header) bytes
 */
#define V4V_ROUNDUP(a) (((a) + 0xf) & ~(typeof(a))0xf)

/*
 * opt_v4v -> Enable v4v boot option, defaults to disabled.
 */
static bool_t __read_mostly opt_v4v = 0;
boolean_param("v4v", opt_v4v);

/*
 * Helper functions
 */

static inline uint16_t
v4v_hash_fn(v4v_ring_id_t *id)
{
    uint16_t ret;

    ret = (uint16_t)(id->addr.port >> 16);
    ret ^= (uint16_t)id->addr.port;
    ret ^= id->addr.domain;
    ret ^= id->partner;

    ret &= (V4V_HTABLE_SIZE - 1);

    return ret;
}

static struct v4v_ring_info *v4v_ring_find_info(struct domain *d,
                                                v4v_ring_id_t *id);

static struct v4v_ring_info *v4v_ring_find_info_by_addr(struct domain *d,
                                                        struct v4v_addr *a,
                                                        domid_t p);

struct list_head v4vtables_rules = LIST_HEAD_INIT(v4vtables_rules);

/*
 * locks
 */

/*
 * locking is organized as follows:
 *
 * the global lock v4v_lock: L1 protects the v4v elements
 * of all struct domain *d in the system, it does not
 * protect any of the elements of d->v4v, just their
 * addresses. By extension since the destruction of
 * a domain with a non-NULL d->v4v will need to free
 * the d->v4v pointer, holding this lock gauruntees
 * that no domains pointers in which v4v is interested
 * become invalid whilst this lock is held.
 */

static DEFINE_RWLOCK(v4v_lock); /* L1 */

/*
 * the lock d->v4v->lock: L2:  Read on protects the hash table and
 * the elements in the hash_table d->v4v->ring_hash, and
 * the node and id fields in struct v4v_ring_info in the
 * hash table. Write on L2 protects all of the elements of
 * struct v4v_ring_info. To take L2 you must already have R(L1)
 * W(L1) implies W(L2) and L3
 *
 * the lock v4v_ring_info *ringinfo; ringinfo->lock: L3:
 * protects len,tx_ptr the guest ring, the
 * guest ring_data and the pending list. To take L3 you must
 * already have R(L2). W(L2) implies L3
 */

/*
 * lock to protect the filtering rules list: v4vtable_rules
 *
 * The write lock is held for v4vtables_del and v4vtables_add
 * The read lock is held for v4vtable_list
 */
static DEFINE_RWLOCK(v4vtables_rules_lock);

/*
 * Debugs
 */

#ifdef V4V_DEBUG
#define v4v_dprintk(format, args...)                    \
    do {                                                \
        printk("%s %s:%d " format,                      \
               __func__, __FILE__, __LINE__, ## args ); \
    } while ( 1 == 0 )
#else
#define v4v_dprintk(format, ... ) (void)0
#endif

#ifdef V4V_DEBUG
static void __attribute__((unused))
v4v_hexdump(void *_p, int len)
{
    uint8_t *buf = (uint8_t *)_p;
    int i, j, k;

    for ( i = 0; i < len; i += 16 )
    {
        printk(XENLOG_G_ERR "%p:", &buf[i]);
        for ( j = 0; j < 16; ++j )
        {
            k = i + j;
            if ( k < len )
                printk(" %02x", buf[k]);
            else
                printk("   ");
        }
        printk(" ");

        for ( j = 0; j < 16; ++j )
        {
            k = i + j;
            if ( k < len )
                printk("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            else
                printk(" ");
        }
        printk("\n");
    }
}
#endif


/*
 * Event channel
 */

static void
v4v_signal_domain(struct domain *d)
{
    v4v_dprintk("send guest VIRQ_V4V domid:%d\n", d->domain_id);

    evtchn_send(d, d->v4v->evtchn_port);
}

static void
v4v_signal_domid(domid_t id)
{
    struct domain *d = get_domain_by_id(id);

    if ( !d )
        return;
    v4v_signal_domain(d);
    put_domain(d);
}


/*
 * ring buffer
 */

static void
v4v_ring_unmap(struct v4v_ring_info *ring_info)
{
    int i;

    ASSERT(spin_is_locked(&ring_info->lock));

    for ( i = 0; i < ring_info->npage; ++i )
    {
        if ( !ring_info->mfn_mapping[i] )
            continue;
        v4v_dprintk("unmapping page %"PRI_mfn" from %p\n",
                    mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);

        unmap_domain_page(ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

static uint8_t *
v4v_ring_map_page(struct v4v_ring_info *ring_info, int i)
{
    ASSERT(spin_is_locked(&ring_info->lock));

    if ( i >= ring_info->npage )
        return NULL;
    if ( ring_info->mfn_mapping[i] )
        return ring_info->mfn_mapping[i];
    ring_info->mfn_mapping[i] = map_domain_page(mfn_x(ring_info->mfns[i]));

    v4v_dprintk("mapping page %"PRI_mfn" to %p\n",
                mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);
    return ring_info->mfn_mapping[i];
}

static int
v4v_memcpy_from_guest_ring(void *_dst, struct v4v_ring_info *ring_info,
                           uint32_t offset, uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *src;
    uint8_t *dst = _dst;

    ASSERT(spin_is_locked(&ring_info->lock));

    offset &= PAGE_SIZE - 1;

    while ( (offset + len) > PAGE_SIZE )
    {
        src = v4v_ring_map_page(ring_info, page);

        if ( !src )
            return -EFAULT;

        v4v_dprintk("memcpy(%p,%p+%d,%d)\n",
                    dst, src, offset, (int)(PAGE_SIZE - offset));
        memcpy(dst, src + offset, PAGE_SIZE - offset);

        page++;
        len -= PAGE_SIZE - offset;
        dst += PAGE_SIZE - offset;
        offset = 0;
    }

    src = v4v_ring_map_page(ring_info, page);
    if ( !src )
        return -EFAULT;

    v4v_dprintk("memcpy(%p,%p+%d,%d)\n", dst, src, offset, len);
    memcpy(dst, src + offset, len);

    return 0;
}

static int
v4v_update_tx_ptr(struct v4v_ring_info *ring_info, uint32_t tx_ptr)
{
    uint8_t *dst = v4v_ring_map_page(ring_info, 0);
    uint32_t *p = (uint32_t *)(dst + offsetof(v4v_ring_t, tx_ptr));

    ASSERT(spin_is_locked(&ring_info->lock));

    if ( !dst )
        return -EFAULT;
    write_atomic(p, tx_ptr);
    mb();
    return 0;
}

static int
v4v_memcpy_to_guest_ring(struct v4v_ring_info *ring_info,
                         uint32_t offset,
                         void *src,
                         XEN_GUEST_HANDLE(uint8_t) src_hnd,
                         uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;

    ASSERT(spin_is_locked(&ring_info->lock));

    offset &= PAGE_SIZE - 1;

    while ( (offset + len) > PAGE_SIZE )
    {
        dst = v4v_ring_map_page(ring_info, page);
        if ( !dst )
            return -EFAULT;

        if ( !src )
        {
            if ( __copy_from_guest(dst + offset, src_hnd, PAGE_SIZE - offset) )
                return -EFAULT;
        }
        else
            memcpy(dst + offset, src, PAGE_SIZE - offset);

        page++;
        len -= PAGE_SIZE - offset;
        if ( src )
            src += (PAGE_SIZE - offset);
        else
            guest_handle_add_offset(src_hnd, PAGE_SIZE - offset);
        offset = 0;
    }

    dst = v4v_ring_map_page(ring_info, page);
    if ( !dst )
        return -EFAULT;

    if ( !src )
    {
        if (  __copy_from_guest(dst + offset, src_hnd, len) )
            return -EFAULT;
    }
    else
        memcpy(dst + offset, src, len);

    return 0;
}

static int
v4v_ringbuf_get_rx_ptr(struct domain *d, struct v4v_ring_info *ring_info,
                        uint32_t * rx_ptr)
{
    v4v_ring_t *ringp;

    if ( ring_info->npage == 0 )
        return -1;

    ringp = map_domain_page(mfn_x(ring_info->mfns[0]));

    v4v_dprintk("mapped %"PRI_mfn" to %p\n",
                mfn_x(ring_info->mfns[0]), ringp);
    if ( !ringp )
        return -1;

    write_atomic(rx_ptr, ringp->rx_ptr);
    mb();

    unmap_domain_page(ringp);
    return 0;
}

uint32_t
v4v_ringbuf_payload_space(struct domain * d, struct v4v_ring_info * ring_info)
{
    v4v_ring_t ring;
    int32_t ret;

    ring.tx_ptr = ring_info->tx_ptr;
    ring.len = ring_info->len;

    if ( v4v_ringbuf_get_rx_ptr(d, ring_info, &ring.rx_ptr) )
        return 0;

    v4v_dprintk("tx_ptr=%d rx_ptr=%d\n", ring.tx_ptr, ring.rx_ptr);
    if ( ring.rx_ptr == ring.tx_ptr )
        return ring.len - sizeof(struct v4v_ring_message_header);

    ret = ring.rx_ptr - ring.tx_ptr;
    if ( ret < 0 )
        ret += ring.len;

    ret -= sizeof(struct v4v_ring_message_header);
    ret -= V4V_ROUNDUP(1);

    return (ret < 0) ? 0 : ret;
}

static long
v4v_iov_count(XEN_GUEST_HANDLE_PARAM(v4v_iov_t) iovs, int niov)
{
    size_t ret = 0;

    while ( niov-- )
    {
        v4v_iov_t iov;

        if ( copy_from_guest(&iov, iovs, 1) )
            return -EFAULT;

        ret += iov.iov_len;

        /* message bigger than 2G can't be sent */
        if (ret > 2L * 1024 * 1024 * 1024)
            return -EMSGSIZE;

        guest_handle_add_offset(iovs, 1);
    }

    return ret;
}

static long
v4v_ringbuf_insertv(struct domain *d,
                    struct v4v_ring_info *ring_info,
                    v4v_ring_id_t *src_id, uint32_t message_type,
                    XEN_GUEST_HANDLE_PARAM(v4v_iov_t) iovs,
                    uint32_t niov, size_t len)
{
    static XEN_GUEST_HANDLE(uint8_t) empty_hnd = { 0 };
    long happy_ret;
    int32_t ret = 0;

    ASSERT(spin_is_locked(&ring_info->lock));

    happy_ret = len;

    if ( (V4V_ROUNDUP(len) + sizeof(struct v4v_ring_message_header) ) >=
            ring_info->len)
        return -EMSGSIZE;

    do {
        v4v_ring_t ring;
        struct v4v_ring_message_header mh = { 0 };
        int32_t sp;

        if ( (ret = v4v_memcpy_from_guest_ring(&ring, ring_info, 0,
                                               sizeof(ring))) )
            break;

        ring.tx_ptr = ring_info->tx_ptr;
        ring.len = ring_info->len;

        v4v_dprintk("ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d\n",
                    ring.tx_ptr, ring.rx_ptr, ring.len);
        v4v_dprintk("ring_info->tx_ptr=%d\n",
                    ring_info->tx_ptr);

        if ( ring.rx_ptr == ring.tx_ptr )
            sp = ring_info->len;
        else
        {
            sp = ring.rx_ptr - ring.tx_ptr;
            if ( sp < 0 )
                sp += ring.len;
        }

        if ( (V4V_ROUNDUP(len) + sizeof(struct v4v_ring_message_header)) >= sp )
        {
            v4v_dprintk("EAGAIN\n");
            ret = -EAGAIN;
            break;
        }

        mh.len = len + sizeof (struct v4v_ring_message_header);
        mh.source.port = src_id->addr.port;
        mh.source.domain = src_id->addr.domain;
        mh.message_type = message_type;

        if ( (ret = v4v_memcpy_to_guest_ring(ring_info,
                                             ring.tx_ptr + sizeof(v4v_ring_t),
                                             &mh, empty_hnd,
                                             sizeof(mh))) )
            break;

        ring.tx_ptr += sizeof(mh);
        if ( ring.tx_ptr == ring_info->len )
            ring.tx_ptr = 0;

        while ( niov-- )
        {
            XEN_GUEST_HANDLE_PARAM(uint8_t) bufp_hnd;
            XEN_GUEST_HANDLE(uint8_t) buf_hnd;
            v4v_iov_t iov;

            if ( copy_from_guest(&iov, iovs, 1) )
            {
                ret = -EFAULT;
                break;
            }

            bufp_hnd = guest_handle_from_ptr(iov.iov_base, uint8_t);
            buf_hnd = guest_handle_from_param(bufp_hnd, uint8_t);
            len = iov.iov_len;

            if ( unlikely(!guest_handle_okay(buf_hnd, len)) )
            {
                ret = -EFAULT;
                break;
            }

            sp = ring.len - ring.tx_ptr;

            if ( len > sp )
            {
                ret = v4v_memcpy_to_guest_ring(ring_info,
                        ring.tx_ptr + sizeof(v4v_ring_t),
                        NULL, buf_hnd, sp);
                if ( ret )
                    break;

                ring.tx_ptr = 0;
                len -= sp;
                guest_handle_add_offset(buf_hnd, sp);
            }

            ret = v4v_memcpy_to_guest_ring(ring_info,
                    ring.tx_ptr + sizeof(v4v_ring_t),
                    NULL, buf_hnd, len);
            if ( ret )
                break;

            ring.tx_ptr += len;

            if ( ring.tx_ptr == ring_info->len )
                ring.tx_ptr = 0;

            guest_handle_add_offset(iovs, 1);
        }
        if ( ret )
            break;

        ring.tx_ptr = V4V_ROUNDUP(ring.tx_ptr);

        if ( ring.tx_ptr >= ring_info->len )
            ring.tx_ptr -= ring_info->len;

        mb();
        ring_info->tx_ptr = ring.tx_ptr;
        if ( (ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)) )
            break;
    } while ( 0 );

    v4v_ring_unmap(ring_info);

    return ret ? ret : happy_ret;
}

/* pending */
static void
v4v_pending_remove_ent(struct v4v_pending_ent *ent)
{
    hlist_del(&ent->node);
    xfree(ent);
}

static void
v4v_pending_remove_all(struct v4v_ring_info *info)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;

    ASSERT(spin_is_locked(&info->lock));
    hlist_for_each_entry_safe(pending_ent, node, next, &info->pending,
            node) v4v_pending_remove_ent(pending_ent);
}

static void
v4v_pending_notify(struct domain *caller_d, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *pending_ent;

    ASSERT(rw_is_locked(&v4v_lock));

    hlist_for_each_entry_safe(pending_ent, node, next, to_notify, node)
    {
        hlist_del(&pending_ent->node);
        v4v_signal_domid(pending_ent->id);
        xfree(pending_ent);
    }
}

static void
v4v_pending_find(struct domain *d, struct v4v_ring_info *ring_info,
                 uint32_t payload_space, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    ASSERT(rw_is_locked(&d->v4v->lock));

    spin_lock(&ring_info->lock);
    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( payload_space >= ent->len )
        {
            hlist_del(&ent->node);
            hlist_add_head(&ent->node, to_notify);
        }
    }
    spin_unlock(&ring_info->lock);
}

/*caller must have L3 */
static int
v4v_pending_queue(struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct v4v_pending_ent *ent = xmalloc(struct v4v_pending_ent);

    if ( !ent )
    {
        v4v_dprintk("ENOMEM\n");
        return -ENOMEM;
    }

    ent->len = len;
    ent->id = src_id;

    hlist_add_head(&ent->node, &ring_info->pending);

    return 0;
}

/* L3 */
static int
v4v_pending_requeue(struct v4v_ring_info *ring_info, domid_t src_id, int len)
{
    struct hlist_node *node;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry(ent, node, &ring_info->pending, node)
    {
        if ( ent->id == src_id )
        {
            if ( ent->len < len )
                ent->len = len;
            return 0;
        }
    }

    return v4v_pending_queue(ring_info, src_id, len);
}


/* L3 */
static void
v4v_pending_cancel(struct v4v_ring_info *ring_info, domid_t src_id)
{
    struct hlist_node *node, *next;
    struct v4v_pending_ent *ent;

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( ent->id == src_id)
        {
            hlist_del(&ent->node);
            xfree(ent);
        }
    }
}

/*
 * ring data
 */

/*Caller should hold R(L1)*/
static int
v4v_fill_ring_data(struct domain *src_d,
                   XEN_GUEST_HANDLE(v4v_ring_data_ent_t) data_ent_hnd)
{
    v4v_ring_data_ent_t ent;
    struct domain *dst_d;

    if ( copy_from_guest(&ent, data_ent_hnd, 1) )
    {
        v4v_dprintk("EFAULT\n");
        return -EFAULT;
    }

    v4v_dprintk("ent.ring.domain=%d,ent.ring.port=%u\n",
                (int)ent.ring.domain, (int)ent.ring.port);

    ent.flags = 0;

    dst_d = get_domain_by_id(ent.ring.domain);

    if ( dst_d && dst_d->v4v )
    {
        struct v4v_ring_info *ring_info;

        read_lock(&dst_d->v4v->lock);
        ring_info = v4v_ring_find_info_by_addr(dst_d, &ent.ring,
                                               src_d->domain_id);

        if ( ring_info )
        {
            uint32_t space_avail;

            ent.flags |= V4V_RING_DATA_F_EXISTS;
            ent.max_message_size =
                ring_info->len - sizeof(struct v4v_ring_message_header) -
                V4V_ROUNDUP(1);
            spin_lock(&ring_info->lock);

            space_avail = v4v_ringbuf_payload_space(dst_d, ring_info);

            if ( space_avail >= ent.space_required )
            {
                v4v_pending_cancel(ring_info, src_d->domain_id);
                ent.flags |= V4V_RING_DATA_F_SUFFICIENT;
            }
            else
            {
                v4v_pending_requeue(ring_info, src_d->domain_id,
                        ent.space_required);
                ent.flags |= V4V_RING_DATA_F_PENDING;
            }

            spin_unlock(&ring_info->lock);

            if ( space_avail == ent.max_message_size )
                ent.flags |= V4V_RING_DATA_F_EMPTY;

        }
        read_unlock(&dst_d->v4v->lock);
    }

    if ( dst_d )
        put_domain(dst_d);

    if ( copy_field_to_guest(data_ent_hnd, &ent, flags) )
    {
        v4v_dprintk("EFAULT\n");
        return -EFAULT;
    }
    return 0;
}

/*Called should hold no more than R(L1) */
static int
v4v_fill_ring_datas(struct domain *d, int nent,
                     XEN_GUEST_HANDLE(v4v_ring_data_ent_t) data_ent_hnd)
{
    int ret = 0;

    read_lock(&v4v_lock);
    while ( !ret && nent-- )
    {
        ret = v4v_fill_ring_data(d, data_ent_hnd);
        guest_handle_add_offset(data_ent_hnd, 1);
    }
    read_unlock(&v4v_lock);

    return ret;
}

/*
 * ring
 */
static int
v4v_find_ring_mfns(struct domain *d, struct v4v_ring_info *ring_info,
                   uint32_t npage, XEN_GUEST_HANDLE_PARAM(v4v_pfn_t) pfn_hnd)
{
    int i;
    mfn_t *mfns;
    uint8_t **mfn_mapping;
    int ret = 0;

    if ( (npage << PAGE_SHIFT) < ring_info->len )
    {
        v4v_dprintk("EINVAL\n");
        return -EINVAL;
    }

    mfns = xmalloc_array(mfn_t, npage);
    if ( !mfns )
    {
        v4v_dprintk("ENOMEM\n");
        return -ENOMEM;
    }

    mfn_mapping = xmalloc_array(uint8_t *, npage);
    if ( !mfn_mapping )
    {
        xfree(mfns);
        return -ENOMEM;
    }

    for ( i = 0; i < npage; ++i )
    {
        unsigned long pfn;
        unsigned long mfn;
        p2m_type_t p2mt;
        struct page_info *page;

        if ( copy_from_guest_offset(&pfn, pfn_hnd, i, 1) )
        {
            v4v_dprintk("EFAULT\n");
            ret = -EFAULT;
            break;
        }

        mfn = mfn_x(get_gfn(d, pfn, &p2mt));
        if ( !mfn_valid(mfn) )
        {
            put_gfn(d, pfn);
            printk(XENLOG_G_ERR
                   "v4v domain %d passed invalid mfn %"PRI_mfn
                   " ring %p seq %d pfn %05lx\n",
                   d->domain_id, mfn, ring_info, i, pfn);
            ret = -EINVAL;
            break;
        }

        if ( p2m_is_paging(p2mt) )
        {
            put_gfn(d, pfn);
            p2m_mem_paging_populate(d, pfn);
            printk(XENLOG_G_WARNING
                   "v4v domain %d passed a mfn that is paging %"PRI_mfn
                   " ring %p seq %d pfn %05lx, try again\n",
                   d->domain_id, mfn, ring_info, i, pfn);
            ret = -EAGAIN;
            break;
        }

        if ( p2m_is_shared(p2mt) || p2m_is_grant(p2mt) )
        {
            put_gfn(d, pfn);
            printk(XENLOG_G_ERR
                   "v4v domain %d passed invalid type mfn %"PRI_mfn
                   " ring %p seq %d pfn %05lx\n",
                   d->domain_id, mfn, ring_info, i, pfn);
            ret = -EINVAL;
            break;
        }

        page = mfn_to_page(mfn);
        if ( !get_page_and_type(page, d, PGT_writable_page) )
        {
            put_gfn(d, pfn);
            printk(XENLOG_G_ERR
                   "v4v domain %d passed wrong type mfn %"PRI_mfn
                   " ring %p seq %d\n pfn %05lx",
                   d->domain_id, mfn, ring_info, i, pfn);
            ret = -EINVAL;
            break;
        }

        mfns[i] = _mfn(mfn);
        v4v_dprintk("%d: %05lx -> %"PRI_mfn"\n", i, pfn, mfn_x(mfns[i]));
        mfn_mapping[i] = NULL;
        put_gfn(d, pfn);
    }

    if ( !ret )
    {
        ring_info->npage = npage;
        ring_info->mfns = mfns;
        ring_info->mfn_mapping = mfn_mapping;
    }
    else
    {
        int j = i;

        for ( i = 0; i < j; ++i )
            if ( mfn_x(mfns[i]) != INVALID_MFN )
                put_page_and_type(mfn_to_page(mfn_x(mfns[i])));
        xfree(mfn_mapping);
        xfree(mfns);
    }

    return ret;
}

static struct v4v_ring_info *
v4v_ring_find_info(struct domain *d, v4v_ring_id_t *id)
{
    uint16_t hash;
    struct hlist_node *node;
    struct v4v_ring_info *ring_info;

    ASSERT(rw_is_locked(&d->v4v->lock));

    hash = v4v_hash_fn(id);

    v4v_dprintk("d->v4v=%p, d->v4v->ring_hash[%d]=%p id=%p\n",
                d->v4v, (int)hash, d->v4v->ring_hash[hash].first, id);
    v4v_dprintk("id.addr.port=%d id.addr.domain=%d id.addr.partner=%d\n",
                id->addr.port, id->addr.domain, id->partner);

    hlist_for_each_entry(ring_info, node, &d->v4v->ring_hash[hash], node)
    {
        v4v_ring_id_t *cmpid = &ring_info->id;

        if ( cmpid->addr.port == id->addr.port &&
             cmpid->addr.domain == id->addr.domain &&
             cmpid->partner == id->partner )
        {
            v4v_dprintk("ring_info=%p\n", ring_info);
            return ring_info;
        }
    }
    v4v_dprintk("no ring_info found\n");
    return NULL;
}

static struct v4v_ring_info *
v4v_ring_find_info_by_addr(struct domain *d, struct v4v_addr *a, domid_t p)
{
    v4v_ring_id_t id;
    struct v4v_ring_info *ret;

    ASSERT(rw_is_locked(&d->v4v->lock));

    if ( !a )
        return NULL;

    id.addr.port = a->port;
    id.addr.domain = d->domain_id;
    id.partner = p;

    ret = v4v_ring_find_info(d, &id);
    if ( ret )
        return ret;

    id.partner = V4V_DOMID_ANY;

    return v4v_ring_find_info(d, &id);
}

static void v4v_ring_remove_mfns(struct domain *d, struct v4v_ring_info *ring_info)
{
    ASSERT(rw_is_write_locked(&d->v4v->lock));

    if ( ring_info->mfns )
    {
        int i;

        for ( i = 0; i < ring_info->npage; ++i )
            if ( mfn_x(ring_info->mfns[i]) != INVALID_MFN )
                put_page_and_type(mfn_to_page(mfn_x(ring_info->mfns[i])));
        xfree(ring_info->mfns);
    }

    xfree(ring_info->mfn_mapping);
    ring_info->mfns = NULL;
}

static void
v4v_ring_remove_info(struct domain *d, struct v4v_ring_info *ring_info, int in_hash)
{
    ASSERT(rw_is_write_locked(&d->v4v->lock));

    spin_lock(&ring_info->lock);

    v4v_pending_remove_all(ring_info);
    if ( in_hash )
        hlist_del(&ring_info->node);
    v4v_ring_remove_mfns(d, ring_info);

    spin_unlock(&ring_info->lock);

    xfree(ring_info);
}

/* Call from guest to unpublish a ring */
static long
v4v_ring_remove(struct domain *d, XEN_GUEST_HANDLE_PARAM(v4v_ring_t) ring_hnd,
                uint32_t ring_type)
{
    int ret = 0;
    int in_hash = 1;

    read_lock(&v4v_lock);

    do {
        struct v4v_ring ring;
        struct v4v_ring_info *ring_info;

        if ( !d->v4v )
        {
            v4v_dprintk("EINVAL\n");
            ret = -EINVAL;
            break;
        }

        if ( copy_from_guest(&ring, ring_hnd, 1) )
        {
            v4v_dprintk("EFAULT\n");
            ret = -EFAULT;
            break;
        }

        if ( ring.magic != V4V_RING_MAGIC )
        {
            v4v_dprintk("ring.magic(%"PRIx64") != V4V_RING_MAGIC(%"PRIx64")\n",
                    ring.magic, V4V_RING_MAGIC);
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;
        write_lock(&d->v4v->lock);

        switch ( ring_type )
        {
        case V4V_RING_TYPE_NOTIFICATION:
            ring_info = d->v4v->ring_notification;
            d->v4v->ring_notification = NULL;
            in_hash = 0;
        case V4V_RING_TYPE_LISTEN:
            ring_info = d->v4v->ring_listen;
            d->v4v->ring_listen = NULL;
            in_hash = 0;
            break;
        default:
            ring_info = v4v_ring_find_info(d, &ring.id);
        }

        if ( ring_info )
            v4v_ring_remove_info(d, ring_info, in_hash);

        write_unlock(&d->v4v->lock);

        if ( !ring_info )
        {
            v4v_dprintk("ENOENT\n");
            ret = -ENOENT;
            break;
        }

    } while ( 0 );

    read_unlock(&v4v_lock);

    return ret;
}

/* call from guest to publish a ring */
static long
v4v_ring_add(struct domain *d, XEN_GUEST_HANDLE_PARAM(v4v_ring_t) ring_hnd,
             uint32_t npage, XEN_GUEST_HANDLE_PARAM(v4v_pfn_t) pfn_hnd,
             uint32_t ring_type)
{
    int ret = 0;

    if ( (long)ring_hnd.p & (PAGE_SIZE - 1) )
    {
        v4v_dprintk("EINVAL\n");
        return -EINVAL;
    }

    read_lock(&v4v_lock);

    do {
        struct v4v_ring ring;
        struct v4v_ring_info *ring_info;
        uint16_t hash;

        if ( !d->v4v )
        {
            v4v_dprintk("!d->v4v, EINVAL\n");
            ret = -EINVAL;
            break;
        }

        read_lock(&d->v4v->lock);
        if ( d->v4v->ring_count >= d->v4v->max_rings )
        {
            read_unlock(&d->v4v->lock);
            v4v_dprintk("ring_count >= max_rings, EACCES\n");
            ret = -EACCES;
            break;
        }
        read_unlock(&d->v4v->lock);

        if ( copy_from_guest(&ring, ring_hnd, 1) )
        {
            v4v_dprintk("copy_from_guest failed, EFAULT\n");
            ret = -EFAULT;
            break;
        }

        if ( ring.magic != V4V_RING_MAGIC )
        {
            v4v_dprintk("ring.magic(%lx) != V4V_RING_MAGIC(%lx)\n",
                        ring.magic, V4V_RING_MAGIC);
            ret = -EINVAL;
            break;
        }

        if ( (ring.len <
                    (sizeof(struct v4v_ring_message_header) + V4V_ROUNDUP(1) +
                     V4V_ROUNDUP(1))) || (V4V_ROUNDUP(ring.len) != ring.len) )
        {
            v4v_dprintk("EINVAL\n");
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain = d->domain_id;
        if ( copy_field_to_guest(ring_hnd, &ring, id) )
        {
            v4v_dprintk("EFAULT\n");
            ret = -EFAULT;
            break;
        }

        /*
         * no need for a lock yet, because only we know about this
         * set the tx pointer if it looks bogus (we don't reset it
         * because this might be a re-register after S4)
         */
        if ( (ring.tx_ptr >= ring.len)
                || (V4V_ROUNDUP(ring.tx_ptr) != ring.tx_ptr) )
        {
            ring.tx_ptr = ring.rx_ptr;
        }
        copy_field_to_guest(ring_hnd, &ring, tx_ptr);

        /* check if the ring already exists */
        if ( ring_type == V4V_RING_TYPE_LISTEN )
        {
            if ( d->v4v->ring_listen )
            {
                ret = -EEXIST;
                break;
            }
        }
        else if ( ring_type == V4V_RING_TYPE_NOTIFICATION )
        {
            if ( d->v4v->ring_notification )
            {
                ret = -EEXIST;
                break;
            }
        }
        else
        {
            read_lock(&d->v4v->lock);

            ring_info = v4v_ring_find_info(d, &ring.id);
            if ( ring_info )
            {
                /* Ring info already exists. */
                read_unlock(&d->v4v->lock);
                printk(XENLOG_WARNING "v4v: dom%d ring already registered\n",
                        current->domain->domain_id);
                ret = -EEXIST;
                break;
            }

            /* Making a new one, lock not needed. */
            read_unlock(&d->v4v->lock);
        }

        ring_info = xmalloc(struct v4v_ring_info);
        if ( !ring_info )
        {
            v4v_dprintk("ENOMEM\n");
            ret = -ENOMEM;
            break;
        }

        spin_lock_init(&ring_info->lock);
        INIT_HLIST_HEAD(&ring_info->pending);
        ring_info->mfns = NULL;
        ring_info->id = ring.id;
        ring_info->len = ring.len;
        ring_info->tx_ptr = ring.tx_ptr;
        ret = v4v_find_ring_mfns(d, ring_info, npage, pfn_hnd);
        if ( ret )
        {
            xfree(ring_info);
            break;
        }


        switch ( ring_type )
        {
        case V4V_RING_TYPE_LISTEN:
            d->v4v->ring_listen = ring_info;
            break;
        case V4V_RING_TYPE_NOTIFICATION:
            d->v4v->ring_notification = ring_info;
            break;
        default:
            hash = v4v_hash_fn(&ring.id);

            write_lock(&d->v4v->lock);
            hlist_add_head(&ring_info->node, &d->v4v->ring_hash[hash]);
            d->v4v->ring_count++;
            write_unlock(&d->v4v->lock);
        }
 
    } while ( 0 );

    read_unlock(&v4v_lock);

    return ret;
}

/*
 * io
 */

static void
v4v_notify_ring(struct domain *d, struct v4v_ring_info *ring_info,
                struct hlist_head *to_notify)
{
    uint32_t space;

    ASSERT(rw_is_locked(&v4v_lock));
    ASSERT(rw_is_locked(&d->v4v->lock));

    spin_lock(&ring_info->lock);
    space = v4v_ringbuf_payload_space(d, ring_info);
    spin_unlock(&ring_info->lock);

    v4v_pending_find(d, ring_info, space, to_notify);
}

/*notify hypercall*/
static long
v4v_notify(struct domain *d,
           XEN_GUEST_HANDLE_PARAM(v4v_ring_data_t) ring_data_hnd)
{
    v4v_ring_data_t ring_data;
    HLIST_HEAD(to_notify);
    int i;
    int ret = 0;

    read_lock(&v4v_lock);

    if ( !d->v4v )
    {
        read_unlock(&v4v_lock);
        v4v_dprintk("!d->v4v, ENODEV\n");
        return -ENODEV;
    }

    read_lock(&d->v4v->lock);
    for ( i = 0; i < V4V_HTABLE_SIZE; ++i )
    {
        struct hlist_node *node, *next;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry_safe(ring_info, node,
                next, &d->v4v->ring_hash[i],
                node)
        {
            v4v_notify_ring(d, ring_info, &to_notify);
        }
    }
    read_unlock(&d->v4v->lock);

    if ( !hlist_empty(&to_notify) )
        v4v_pending_notify(d, &to_notify);

    do {
        if ( !guest_handle_is_null(ring_data_hnd) )
        {
            /* Quick sanity check on ring_data_hnd */
            if ( copy_field_from_guest(&ring_data, ring_data_hnd, magic) )
            {
                v4v_dprintk("copy_field_from_guest failed\n");
                ret = -EFAULT;
                break;
            }

            if ( ring_data.magic != V4V_RING_DATA_MAGIC )
            {
                v4v_dprintk("ring.magic(%lx) != V4V_RING_MAGIC(%lx)\n",
                        ring_data.magic, V4V_RING_MAGIC);
                ret = -EINVAL;
                break;
            }

            if ( copy_from_guest(&ring_data, ring_data_hnd, 1) )
            {
                v4v_dprintk("copy_from_guest failed\n");
                ret = -EFAULT;
                break;
            }

            read_lock(&d->v4v->lock);
            if ( ring_data.nent > d->v4v->max_notify )
            {
                read_unlock(&d->v4v->lock);
                v4v_dprintk("ring_date.nent > max_notify, EACCES\n");
                ret = -EACCES;
                break;
            }
            read_unlock(&d->v4v->lock);

            {
                /* This is a guest pointer passed as a field in a struct
                 * so XEN_GUEST_HANDLE is used. */
                XEN_GUEST_HANDLE(v4v_ring_data_ent_t) ring_data_ent_hnd;
                ring_data_ent_hnd =
                    guest_handle_for_field(ring_data_hnd, v4v_ring_data_ent_t, data[0]);
                ret = v4v_fill_ring_datas(d, ring_data.nent, ring_data_ent_hnd);
            }
        }
    } while ( 0 );

    read_unlock(&v4v_lock);

    return ret;
}

static long
v4v_config(XEN_GUEST_HANDLE_PARAM(v4v_config_t) config_hnd)
{
    int ret = 0;

    read_lock(&v4v_lock);

    do {
        struct v4v_config config;
        struct domain *target_d;

        if ( copy_from_guest(&config, config_hnd, 1) )
        {
            v4v_dprintk("copy_from_guest failed, EFAULT\n");
            ret = -EFAULT;
            break;
        }

        target_d = get_domain_by_id(config.target_id);

        if ( !target_d )
        {
            v4v_dprintk("!target_d, EINVAL\n");
            ret = -EINVAL;
            break;
        }

        if ( !target_d->v4v )
        {
            v4v_dprintk("!target_d->v4v, EINVAL\n");
            ret = -EINVAL;
            break;
        }

        write_lock(&target_d->v4v->lock);
        /* Cannot change configuration after guest has active rings */
        if ( target_d->v4v->ring_count > 0 )
        {
            write_unlock(&target_d->v4v->lock);
            put_domain(target_d);
            v4v_dprintk("dom%d has active rings, cannot change config\n",
                        config.target_id);
            ret = -EINVAL;
            break;
        }

        target_d->v4v->max_rings = config.max_rings;
        target_d->v4v->max_sendv = config.max_sendv;
        target_d->v4v->max_notify = config.max_notify;
        target_d->v4v->max_send_size = config.max_send_size;
        write_unlock(&target_d->v4v->lock);
        put_domain(target_d);

        v4v_dprintk("set new v4v config for domain %d\n", config.target_id);
        v4v_dprintk("max_rings: 0x%x max_sendv: 0x%x "
                    "max_notify: 0x%x max_send_size: 0x%x",
                    config.max_rings, config.max_sendv,
                    config.max_notify, config.max_send_size);

    } while ( 0 );

    read_unlock(&v4v_lock);

    return ret;
}

#ifdef V4V_DEBUG
void
v4vtables_print_rule(struct v4vtables_rule_node *node)
{
    v4vtables_rule_t *rule;

    if ( node == NULL )
    {
        printk("(null)\n");
        return;
    }

    rule = &node->rule;

    if ( rule->accept == 1 )
        printk("ACCEPT");
    else
        printk("REJECT");

    printk(" ");

    if ( rule->src.domain == V4V_DOMID_ANY )
        printk("*");
    else
        printk("%i", rule->src.domain);

    printk(":");

    if ( rule->src.port == -1 )
        printk("*");
    else
        printk("%i", rule->src.port);

    printk(" -> ");

    if ( rule->dst.domain == V4V_DOMID_ANY )
        printk("*");
    else
        printk("%i", rule->dst.domain);

    printk(":");

    if ( rule->dst.port == -1 )
        printk("*");
    else
        printk("%i", rule->dst.port);

    printk("\n");
}
#endif /* V4V_DEBUG */

int
v4vtables_add(struct domain *src_d,
              XEN_GUEST_HANDLE_PARAM(v4vtables_rule_t) rule,
              int32_t position)
{
    struct v4vtables_rule_node* new = NULL;
    struct list_head* tmp;

    ASSERT(rw_is_write_locked(&v4vtables_rules_lock));

    /* First rule is n.1 */
    position--;

    new = xmalloc(struct v4vtables_rule_node);
    if ( new == NULL )
        return -ENOMEM;

    if ( copy_from_guest(&new->rule, rule, 1) )
    {
        xfree(new);
        return -EFAULT;
    }

#ifdef V4V_DEBUG
    printk(XENLOG_ERR "VIPTables: ");
    v4vtables_print_rule(new);
#endif /* V4V_DEBUG */

    tmp = &v4vtables_rules;
    while ( position != 0 && tmp->next != &v4vtables_rules)
    {
        tmp = tmp->next;
        position--;
    }
    list_add(&new->list, tmp);

    return 0;
}

int
v4vtables_del(struct domain *src_d,
              XEN_GUEST_HANDLE_PARAM(v4vtables_rule_t) rule_hnd,
              int32_t position)
{
    struct list_head *tmp = NULL;
    struct list_head *to_delete = NULL;
    struct list_head *next = NULL;
    struct v4vtables_rule_node *node;

    ASSERT(rw_is_write_locked(&v4vtables_rules_lock));

    v4v_dprintk("position:%d\n", position);

    if ( position != -1 )
    {
        /* We want to delete the rule number <position> */
        list_for_each(tmp, &v4vtables_rules)
        {
            to_delete = tmp;
            if (position == 0)
                break;
            position--;
        }
        /* Can't find the position */
        if (position != 0)
            to_delete = NULL;
    }
    else if ( !guest_handle_is_null(rule_hnd) )
    {
        struct v4vtables_rule r;

        if ( copy_from_guest(&r, rule_hnd, 1) )
            return -EFAULT;

        list_for_each(tmp, &v4vtables_rules)
        {
            node = list_entry(tmp, struct v4vtables_rule_node, list);

            if ( (node->rule.src.domain == r.src.domain) &&
                 (node->rule.src.port   == r.src.port)   &&
                 (node->rule.dst.domain == r.dst.domain) &&
                 (node->rule.dst.port   == r.dst.port))
            {
                to_delete = tmp;
                break;
            }
        }
    }
    else
    {
        /* We want to flush the rules! */
        printk(XENLOG_ERR "VIPTables: flushing rules\n");
        list_for_each_safe(tmp, next, &v4vtables_rules)
        {
            node = list_entry(tmp, struct v4vtables_rule_node, list);
            list_del(tmp);
            xfree(node);
        }
    }

    if ( to_delete )
    {
        node = list_entry(to_delete, struct v4vtables_rule_node, list);
#ifdef V4V_DEBUG
        printk(XENLOG_ERR "VIPTables: deleting rule: ");
        v4vtables_print_rule(node);
#endif /* V4V_DEBUG */
        list_del(to_delete);
        xfree(node);
    }

    return 0;
}

static size_t
v4vtables_list(struct domain *src_d,
               XEN_GUEST_HANDLE_PARAM(v4vtables_list_t) list_hnd)
{
    struct list_head *ptr;
    struct v4vtables_rule_node *node;
    struct v4vtables_list rules_list;
    uint32_t nbrules;
    XEN_GUEST_HANDLE(v4vtables_rule_t) guest_rules;

    ASSERT(rw_is_locked(&v4vtables_rules_lock));

    memset(&rules_list, 0, sizeof (rules_list));
    if ( copy_from_guest(&rules_list, list_hnd, 1) )
        return -EFAULT;

    ptr = v4vtables_rules.next;
    while ( rules_list.start_rule != 0 && ptr->next != &v4vtables_rules )
    {
        ptr = ptr->next;
        rules_list.start_rule--;
    }

    if ( rules_list.nb_rules == 0 )
        return -EINVAL;

    guest_rules = guest_handle_for_field(list_hnd, v4vtables_rule_t, rules[0]);

    nbrules = 0;
    while ( nbrules < rules_list.nb_rules && ptr != &v4vtables_rules )
    {
        node = list_entry(ptr, struct v4vtables_rule_node, list);

        if ( copy_to_guest(guest_rules, &node->rule, 1) )
            break;

        guest_handle_add_offset(guest_rules, 1);

        nbrules++;
        ptr = ptr->next;
    }

    rules_list.nb_rules = nbrules;
    if ( copy_field_to_guest(list_hnd, &rules_list, nb_rules) )
        return -EFAULT;

    return 0;
}

static size_t
v4vtables_check(v4v_addr_t *src, v4v_addr_t *dst)
{
    struct list_head *ptr;
    struct v4vtables_rule_node *node;
    size_t ret = 0; /* Defaulting to ACCEPT */

    read_lock(&v4vtables_rules_lock);

    list_for_each(ptr, &v4vtables_rules)
    {
        node = list_entry(ptr, struct v4vtables_rule_node, list);

        if ( (node->rule.src.domain == V4V_DOMID_ANY ||
              node->rule.src.domain == src->domain) &&
             (node->rule.src.port == V4V_PORT_ANY ||
              node->rule.src.port == src->port) &&
             (node->rule.dst.domain == V4V_DOMID_ANY ||
              node->rule.dst.domain == dst->domain) &&
             (node->rule.dst.port == V4V_PORT_ANY ||
              node->rule.dst.port == dst->port) )
        {
            ret = !node->rule.accept;
            break;
        }
    }

    read_unlock(&v4vtables_rules_lock);
    return ret;
}

/*
 * Hypercall to do the send
 */
static long
v4v_sendv(struct domain *src_d, v4v_addr_t *src_addr,
          v4v_addr_t *dst_addr, uint32_t message_type,
          XEN_GUEST_HANDLE_PARAM(v4v_iov_t) iovs, size_t niov)
{
    struct domain *dst_d;
    v4v_ring_id_t src_id;
    long ret = 0;

    if ( !dst_addr )
    {
        v4v_dprintk("!dst_addr, EINVAL\n");
        return -EINVAL;
    }

    read_lock(&v4v_lock);

    if ( !src_d->v4v )
    {
        read_unlock(&v4v_lock);
        v4v_dprintk("!src_d->v4v, EINVAL\n");
        return -EINVAL;
    }

    read_lock(&src_d->v4v->lock);
    if ( niov > src_d->v4v->max_sendv )
    {
        read_unlock(&src_d->v4v->lock);
        read_unlock(&v4v_lock);
        v4v_dprintk("niov > max_sendv, EACCES\n");
        return -EACCES;
    }
    read_unlock(&src_d->v4v->lock);

    src_id.addr.pad = 0;
    src_id.addr.port = src_addr->port;
    src_id.addr.domain = src_d->domain_id;
    src_id.partner = dst_addr->domain;

    dst_d = get_domain_by_id(dst_addr->domain);
    if ( !dst_d )
    {
        read_unlock(&v4v_lock);
        v4v_dprintk("!dst_d, EINVAL\n");
        return -EINVAL;
    }

    if ( v4vtables_check(src_addr, dst_addr) != 0 )
    {
        read_unlock(&v4v_lock);
        printk(XENLOG_G_WARNING
               "V4V: VIPTables REJECTED %i:%i -> %i:%i\n",
               src_addr->domain, src_addr->port,
               dst_addr->domain, dst_addr->port);
        return -ECONNREFUSED;
    }

    do {
        struct v4v_ring_info *ring_info;

        if ( !dst_d->v4v )
        {
            v4v_dprintk("dst_d->v4v, ECONNREFUSED\n");
            ret = -ECONNREFUSED;
            break;
        }

        read_lock(&dst_d->v4v->lock);
        ring_info =
            v4v_ring_find_info_by_addr(dst_d, dst_addr, src_addr->domain);

        if ( !ring_info )
        {
            ret = -ECONNREFUSED;
            v4v_dprintk("!ring_info, ECONNREFUSED\n");
        }
        else
        {
            long len = v4v_iov_count(iovs, niov);

            if ( len < 0 )
            {
                ret = len;
                break;
            }

            read_lock(&src_d->v4v->lock);
            if ( len > src_d->v4v->max_send_size )
            {
                read_unlock(&src_d->v4v->lock);
                v4v_dprintk("len > max_send_size, EACCES\n");
                ret = EACCES;
                break;
            }
            read_unlock(&src_d->v4v->lock);

            spin_lock(&ring_info->lock);
            ret =
                v4v_ringbuf_insertv(dst_d, ring_info, &src_id, message_type,
                        iovs, niov, len);
            if ( ret == -EAGAIN )
            {
                v4v_dprintk("v4v_ringbuf_insertv failed, EAGAIN\n");
                /* Schedule a wake up on the event channel when space is there */
                if ( v4v_pending_requeue(ring_info, src_d->domain_id, len) )
                {
                    v4v_dprintk("v4v_pending_requeue failed, ENOMEM\n");
                    ret = -ENOMEM;
                }
            }
            spin_unlock(&ring_info->lock);

            if ( ret >= 0 )
            {
                v4v_signal_domain(dst_d);
            }

        }
        read_unlock(&dst_d->v4v->lock);

    } while ( 0 );

    put_domain(dst_d);
    read_unlock(&v4v_lock);

    return ret;
}

static int
v4v_ring_insert_simple(struct v4v_ring_info *ring_info, unsigned char *data, unsigned int len)
{
    v4v_ring_t ring;
    static XEN_GUEST_HANDLE(uint8_t) empty_hnd = { 0 };
    int ret;

    if ( (ret = v4v_memcpy_from_guest_ring(&ring, ring_info, 0,
                                           sizeof(ring))) )
        return ret;

    ring.tx_ptr = ring_info->tx_ptr;
    ring.len = ring_info->len;

    ret = v4v_memcpy_to_guest_ring(ring_info,
                                   ring.tx_ptr + sizeof(v4v_ring_t),
                                   data, empty_hnd, len);
    if ( ret )
        return ret;

    ring.tx_ptr += len;
    if ( ring.tx_ptr >= ring_info->len )
        ring.tx_ptr = 0;

    mb();
    ring_info->tx_ptr = ring.tx_ptr;
    if ( (ret = v4v_update_tx_ptr(ring_info, ring.tx_ptr)) )
        return ret;
    v4v_ring_unmap(ring_info);

    return 0;
}

static long
v4v_connect(struct domain *src_d, v4v_send_addr_t *send_addr)
{
    int ret = 0;
    struct domain *dst_d;
    v4v_addr_t *src_addr = &send_addr->src;
    v4v_addr_t *dst_addr = &send_addr->dst;

    read_lock(&v4v_lock);

    if ( !src_d->v4v )
    {
        read_unlock(&v4v_lock);
        v4v_dprintk("!src_d->v4v, EINVAL\n");
        return -EINVAL;
    }

    src_addr->domain = src_d->domain_id;

    dst_d = get_domain_by_id(dst_addr->domain);
    if ( !dst_d )
    {
        read_unlock(&v4v_lock);
        v4v_dprintk("!dst_d, EINVAL\n");
        return -EINVAL;
    }

    do {
        struct v4v_ring_info *ring_info;

        if ( !dst_d->v4v )
        {
            v4v_dprintk("dst_d->v4v, ECONNREFUSED\n");
            ret = -ECONNREFUSED;
            break;
        }

        read_lock(&dst_d->v4v->lock);

        ring_info = dst_d->v4v->ring_listen;
        if ( !ring_info )
        {
            ret = -ECONNREFUSED;
            v4v_dprintk("!ring_info, ECONNREFUSED\n");
        }
        else
        {
            spin_lock(&ring_info->lock);
            ret = v4v_ring_insert_simple(ring_info, (unsigned char *) send_addr, sizeof(v4v_send_addr_t));
            spin_unlock(&ring_info->lock);

            if ( ret >= 0 )
            {
                v4v_signal_domain(dst_d);
            }

        }
        read_unlock(&dst_d->v4v->lock);

    } while ( 0 );

    put_domain(dst_d);
    read_unlock(&v4v_lock);

    return ret;
}

static void
v4v_info(struct domain *d, v4v_info_t *info)
{
    read_lock(&d->v4v->lock);
    info->ring_magic = V4V_RING_MAGIC;
    info->data_magic = V4V_RING_DATA_MAGIC;
    info->evtchn = d->v4v->evtchn_port;
    info->max_rings = d->v4v->max_rings;
    info->max_sendv = d->v4v->max_sendv;
    info->max_notify = d->v4v->max_notify;
    info->max_send_size = d->v4v->max_send_size;
    read_unlock(&d->v4v->lock);
}

/*
 * hypercall glue
 */
long
do_v4v_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
          XEN_GUEST_HANDLE_PARAM(void) arg2,
          uint32_t arg3, uint32_t arg4)
{
    struct domain *d = current->domain;
    long rc = -EFAULT;

    if ( !opt_v4v )
    {
        v4v_dprintk("opt_v4v is disabled, no v4v services available\n");
        return -ENOSYS;
    }

    v4v_dprintk("->do_v4v_op(%d,%p,%p,%d,%d)\n", cmd,
                (void *)arg1.p, (void *)arg2.p, (int)arg3, (int)arg4);

    domain_lock(d);
    switch (cmd)
    {
    case V4VOP_register_ring:
    {
         XEN_GUEST_HANDLE_PARAM(v4v_ring_t) ring_hnd =
                 guest_handle_cast(arg1, v4v_ring_t);
         XEN_GUEST_HANDLE_PARAM(v4v_pfn_t) pfn_hnd =
                 guest_handle_cast(arg2, v4v_pfn_t);
         uint32_t npage = arg3;
         uint32_t ring_type = arg4;

         if ( unlikely(!guest_handle_okay(pfn_hnd, npage)) )
             goto out;
         rc = v4v_ring_add(d, ring_hnd, npage, pfn_hnd, ring_type);
         break;
    }
    case V4VOP_unregister_ring:
    {
         XEN_GUEST_HANDLE_PARAM(v4v_ring_t) ring_hnd =
                 guest_handle_cast(arg1, v4v_ring_t);
         /* FIXME no cast to uint64_t */
         rc = v4v_ring_remove(d, ring_hnd, (uint64_t) arg2.p);
         break;
    }
    case V4VOP_sendv:
    {
        uint32_t niov = arg3;
        uint32_t message_type = arg4;

        XEN_GUEST_HANDLE_PARAM(v4v_send_addr_t) addr_hnd =
                guest_handle_cast(arg1, v4v_send_addr_t);
        v4v_send_addr_t addr;

        if ( copy_from_guest(&addr, addr_hnd, 1) )
            goto out;

        rc = v4v_sendv(d, &addr.src, &addr.dst, message_type,
                guest_handle_cast(arg2, v4v_iov_t), niov);
        break;
    }
    case V4VOP_connect:
    {
        XEN_GUEST_HANDLE_PARAM(v4v_send_addr_t) addr_hnd =
                guest_handle_cast(arg1, v4v_send_addr_t);
        v4v_send_addr_t addr;

        if ( copy_from_guest(&addr, addr_hnd, 1) )
            goto out;

        rc = v4v_connect(d, &addr);
        break;
    }
    case V4VOP_notify:
    {
        XEN_GUEST_HANDLE_PARAM(v4v_ring_data_t) ring_data_hnd =
                   guest_handle_cast(arg1, v4v_ring_data_t);
        rc = v4v_notify(d, ring_data_hnd);
        break;
    }
    case V4VOP_info:
    {
        XEN_GUEST_HANDLE_PARAM(v4v_info_t) info_hnd =
               guest_handle_cast(arg1, v4v_info_t);
        v4v_info_t info;

        if ( unlikely(!guest_handle_okay(info_hnd, 1)) )
            goto out;
        v4v_info(d, &info);
        if ( __copy_to_guest(info_hnd, &info, 1) )
            goto out;
        rc = 0;
        break;
    }
    case V4VOP_config:
    {
        XEN_GUEST_HANDLE_PARAM(v4v_config_t) config_hnd =
                   guest_handle_cast(arg1, v4v_config_t);
        /* TODO use XSM check here. This will be addressed
         * with the pending work for the v4vtables.
         */
        rc = -EPERM;
        if ( !is_control_domain(d) )
            goto out;

        rc = v4v_config(config_hnd);
        break;
    }
    case V4VOP_tables_add:
    {
        uint32_t position = arg3;

        XEN_GUEST_HANDLE_PARAM(v4vtables_rule_t) rule_hnd =
               guest_handle_cast(arg1, v4vtables_rule_t);
        rc = -EPERM;
        if ( !is_hardware_domain(d) )
            goto out;

        write_lock(&v4vtables_rules_lock);
        rc = v4vtables_add(d, rule_hnd, position);
        write_unlock(&v4vtables_rules_lock);
        break;
    }
    case V4VOP_tables_del:
    {
        uint32_t position = arg3;

        XEN_GUEST_HANDLE_PARAM(v4vtables_rule_t) rule_hnd =
               guest_handle_cast(arg1, v4vtables_rule_t);
        rc = -EPERM;
        if ( !is_hardware_domain(d) )
             goto out;

        write_lock(&v4vtables_rules_lock);
        rc = v4vtables_del(d, rule_hnd, position);
        write_unlock(&v4vtables_rules_lock);
        break;
    }
    case V4VOP_tables_list:
    {
        XEN_GUEST_HANDLE_PARAM(v4vtables_list_t) rules_list_hnd =
               guest_handle_cast(arg1, v4vtables_list_t);
        rc = -EPERM;
        if ( !is_hardware_domain(d) )
            goto out;

        read_lock(&v4vtables_rules_lock);
        rc = v4vtables_list(d, rules_list_hnd);
        read_unlock(&v4vtables_rules_lock);
        break;
    }
    default:
        rc = -ENOSYS;
        break;
    }
out:
    domain_unlock(d);
    v4v_dprintk("<-do_v4v_op()=%d\n", (int)rc);
    return rc;
}

/*
 * init
 */

bool_t
v4v_get_opt_v4v(void)
{
    return opt_v4v;
}

void
v4v_destroy(struct domain *d)
{
    BUG_ON(!d->is_dying);

    write_lock(&v4v_lock);

    v4v_dprintk("d->v=%p\n", d->v4v);

    if ( d->v4v )
    {
        int i;

        write_lock(&d->v4v->lock);
        for ( i = 0; i < V4V_HTABLE_SIZE; ++i )
        {
            struct hlist_node *node, *next;
            struct v4v_ring_info *ring_info;

            hlist_for_each_entry_safe(ring_info, node,
                    next, &d->v4v->ring_hash[i],
                    node)
            {
                v4v_ring_remove_info(d, ring_info, 1);
            }
        }
        if ( d->v4v->ring_notification )
            v4v_ring_remove_info(d, d->v4v->ring_notification, 0);
        if ( d->v4v->ring_listen )
            v4v_ring_remove_info(d, d->v4v->ring_listen, 0);
        write_unlock(&d->v4v->lock);
    }

    d->v4v = NULL;

    write_unlock(&v4v_lock);
}

int
v4v_init(struct domain *d)
{
    struct v4v_domain *v4v;
    evtchn_port_t port;
    int i;
    int rc;

    v4v = xmalloc(struct v4v_domain);
    if ( !v4v )
        return -ENOMEM;

    rc = evtchn_alloc_unbound_domain(d, &port, d->domain_id, 0);
    if ( rc )
        return rc;

    rwlock_init(&v4v->lock);

    v4v->evtchn_port = port;

    /* Setup default configuration, internal limits */
    v4v->max_rings = V4V_DEFAULT_MAX_RINGS;
    v4v->max_sendv = V4V_DEFAULT_MAX_SENDV;
    v4v->max_notify = V4V_DEFAULT_MAX_NOTIFY;
    v4v->max_send_size = V4V_DEFAULT_MAX_SEND_SIZE;
    v4v->ring_count = 0;
    v4v->ring_notification = NULL;
    v4v->ring_listen = NULL;

    for ( i = 0; i < V4V_HTABLE_SIZE; ++i )
        INIT_HLIST_HEAD(&v4v->ring_hash[i]);

    write_lock(&v4v_lock);
    d->v4v = v4v;
    write_unlock(&v4v_lock);

    return 0;
}


/*
 * debug
 */

static void
dump_domain_ring(struct domain *d, struct v4v_ring_info *ring_info)
{
    uint32_t rx_ptr;

    printk(XENLOG_ERR "  ring: domid=%d port=0x%08x partner=%d npage=%d\n",
           (int)d->domain_id, (int)ring_info->id.addr.port,
           (int)ring_info->id.partner, (int)ring_info->npage);

    if ( v4v_ringbuf_get_rx_ptr(d, ring_info, &rx_ptr) )
    {
        printk(XENLOG_ERR "   Failed to read rx_ptr\n");
        return;
    }

    printk(XENLOG_ERR "   tx_ptr=%d rx_ptr=%d len=%d\n",
           (int)ring_info->tx_ptr, (int)rx_ptr, (int)ring_info->len);
}

static void
dump_domain(struct domain *d)
{
    int i;

    printk(XENLOG_ERR " domain %d:\n", (int)d->domain_id);

    read_lock(&d->v4v->lock);

    for ( i = 0; i < V4V_HTABLE_SIZE; ++i )
    {
        struct hlist_node *node;
        struct v4v_ring_info *ring_info;

        hlist_for_each_entry(ring_info, node, &d->v4v->ring_hash[i], node)
            dump_domain_ring(d, ring_info);
    }

    printk(XENLOG_ERR "  event channel: %d\n",  d->v4v->evtchn_port);
    read_unlock(&d->v4v->lock);

    printk(XENLOG_ERR "\n");
    v4v_signal_domain(d);
}

static void
dump_state(unsigned char key)
{
    struct domain *d;

    printk(XENLOG_ERR "\n\nV4V:\n");
    read_lock(&v4v_lock);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
        dump_domain(d);

    rcu_read_unlock(&domlist_read_lock);

    read_unlock(&v4v_lock);
}

struct keyhandler v4v_info_keyhandler =
{
    .diagnostic = 1,
    .u.fn = dump_state,
    .desc = "dump v4v states and interrupt"
};

static int __init
setup_dump_rings(void)
{
    register_keyhandler('4', &v4v_info_keyhandler);
    return 0;
}

__initcall(setup_dump_rings);

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
