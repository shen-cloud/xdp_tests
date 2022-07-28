#include <linux/types.h>
#include <linux/if_xdp.h>

// mostly stolen from xsk.h
#define __XSK_READ_ONCE(x) (*(volatile typeof(x) *)&x)
#define __XSK_WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)

# define smp_store_release(p, v)					\
	do {								\
		asm volatile("" : : : "memory");			\
		__XSK_WRITE_ONCE(*p, v);				\
	} while (0)
# define smp_load_acquire(p)					\
	({								\
		typeof(*p) ___p1 = __XSK_READ_ONCE(*p);			\
		asm volatile("" : : : "memory");			\
		___p1;							\
	})

struct umem_ring {
        __u32 cached_prod;
        __u32 cached_cons; //actually `size` bigger than consumer on sender side
        __u32 size;
        __u32 *producer;
        __u32 *consumer;
        __u64 *ring;
};

struct kernel_ring {
        __u32 cached_prod;
        __u32 cached_cons; //actually `size` bigger than consumer on sender side
        __u32 size;
        __u32 *producer;
        __u32 *consumer;
        struct xdp_desc *ring;
};

int prod_idx=0;
int cons_idx=0;

static inline __u32 debug_umem_cons(struct umem_ring* u)
{
	__u32 res;
	res = smp_load_acquire(u->consumer);
	return res;
}	
static inline __u32 debug_umem_prod(struct umem_ring* u)
{
	__u32 res;
	res = smp_load_acquire(u->producer);
	return res;
}	

static inline __u32 xsk_umem_prod_nb_free(struct umem_ring *r, __u32 nb)
{
	__u32 free_entries = r->cached_cons - r->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer.
	 * cached_cons is r->size bigger than the real consumer pointer so
	 * that this addition can be avoided in the more frequently
	 * executed code that computs free_entries in the beginning of
	 * this function. Without this optimization it whould have been
	 * free_entries = r->cached_prod - r->cached_cons + r->size.
	 */
	r->cached_cons = smp_load_acquire(r->consumer);
	r->cached_cons += r->size;

	return r->cached_cons - r->cached_prod;
}

static inline __u32 xsk_umem_prod_reserve(struct umem_ring *prod, __u32 nb)
{
	if (xsk_umem_prod_nb_free(prod, nb) < nb)
		return 0;
	prod->cached_prod += nb;

	return nb;
}
// this is an optimization given we know RING_SIZE at compile time
/*
static inline void xsk_umem_ring_prod_write(struct umem_ring *prod, __u64 nb)
{
	prod->ring[prod_idx & prod->size-1];
}
*/
static inline void xsk_umem_prod_write(struct umem_ring *prod, __u64 val)
{
	prod->ring[prod_idx++ & (RING_SIZE*4096l)-1] = val;
}
static inline void xsk_umem_prod_submit(struct umem_ring *prod, __u32 nb)
{
	/* Make sure everything has been written to the ring before indicating
	 * this to the kernel by writing the producer pointer.
	 */
	smp_store_release(prod->producer, *prod->producer + nb);
}

static inline __u32 xsk_kr_cons_nb_avail(struct kernel_ring *r, __u32 nb)
{
	__u32 entries = r->cached_prod - r->cached_cons;

	// maybe this should be `< nb`? not sure why it isnt
	if (entries == 0) {
		r->cached_prod = smp_load_acquire(r->producer);
		entries = r->cached_prod - r->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}


static inline __u32 xsk_kr_cons_peek(struct kernel_ring *cons, __u32 nb)
{
	__u32 entries = xsk_kr_cons_nb_avail(cons, nb);

	if (entries > 0) {
		cons->cached_cons += entries;
	}

	return entries;
}

static inline struct xdp_desc* xsk_umem_cons_read(struct kernel_ring *cons)
{
	return &cons->ring[cons_idx++ & (RING_SIZE*4096)-1];
}

static inline void xsk_kr_cons_release(struct kernel_ring *cons, __u32 nb)
{
	/* Make sure data has been read before indicating we are done
	 * with the entries by updating the consumer pointer.
	 */
	smp_store_release(cons->consumer, *cons->consumer + nb);

}
