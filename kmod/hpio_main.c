#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/smp.h>
#include <linux/err.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/pid.h>
#include <linux/if_ether.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/socket.h>
#include <uapi/linux/ip.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>
#include <net/net_namespace.h>
#include <net/sock.h>


#include <hpio.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#define DRV_NAME	"hpio"
#define HPIO_VERSION	"0.0.0"
MODULE_VERSION(HPIO_VERSION);
MODULE_AUTHOR("haeena.net");
MODULE_DESCRIPTION("haeena packet i/o");
MODULE_LICENSE("GPL");

/* Specific ToS Fieled value:
 * - If this value is configured (not 0), hpio consumes packets having
 * the value in their ToS fields.
 */
static unsigned int tos_consumed __read_mostly = 0;
module_param_named(tos_value, tos_consumed, uint, 0444);
MODULE_PARM_DESC(tos_value, "ToS value consumed by hpio");



#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 8, 0)
bool netdev_is_rx_handler_busy(struct net_device *dev)
{
	ASSERT_RTNL();
	return dev && rtnl_dereference(dev->rx_handler);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 9, 0)
#define hwtstamp	hwtstamp.tv64
#else
/* ktime_t was changed from union to s64 since kernel 4.10 */
#define hwtstamp	hwtstamp
#endif


#define packet_copy_len(pktlen, buflen) \
	buflen > pktlen + sizeof(struct hpio_hdr) ? \
	pktlen : buflen - sizeof(struct hpio_hdr)


/* waitqueue for poll */
static DECLARE_WAIT_QUEUE_HEAD(hpio_wait);


/* packet buffer ring structure */
struct hpio_ring {
	uint16_t	cpu;

	uint32_t	head;	/* write point */
	uint32_t	tail;	/* read point */
	uint32_t	mask;	/* bit mask of ring buffer */

	struct sk_buff *skb_array[HPIO_SLOT_NUM];
	struct sk_buff *skb_tx_array[HPIO_SLOT_NUM]; /* ptr for cloned skb */
};


/* hpio device structure */
struct hpio_dev {
	struct list_head	list;	/* hpio->dev_list */

	struct net_device	*dev;	/* net device */
	struct miscdevice	mdev;	/* character device */
	char 			path[10 + IFNAMSIZ]; /* cdev path */

	uint8_t			num_rings;	/* min (cpu, queue)*/
	struct hpio_ring	*rx_rings;
	struct hpio_ring	*tx_rings;

	pid_t pid;	/* pid of the process open this hpio device */

	atomic_t	refcnt;	/* refrenced by hpio_sock */
};
#define hpio_get_ring(h, idx, di) &((h)->di##_rings[idx])


/* hpio socket structure */
struct hpio_sock {
	struct sock sk;
	struct hpio_dev *hpdev;
};


static unsigned int hpio_net_id;

/* per netnamespace structure */
struct hpio_net {
	struct list_head	dev_list;	/* hpio_dev list */
};



/* hpio global structure operations */

static inline struct hpio_dev *hpio_find_dev(struct net *net,
					     struct net_device *dev)
{
	struct hpio_dev *hpdev;
	struct hpio_net *hpnet;

	hpnet = (struct hpio_net *) net_generic(net, hpio_net_id);

	list_for_each_entry(hpdev, &hpnet->dev_list, list) {
		if (hpdev->dev == dev)
			return hpdev;
	}
	return NULL;
}

static inline struct hpio_dev *hpio_find_dev_by_index(struct net *net,
						      int ifindex)
{
	struct hpio_dev *hpdev;
	struct hpio_net *hpnet;

	hpnet = (struct hpio_net *) net_generic(net, hpio_net_id);

	list_for_each_entry(hpdev, &hpnet->dev_list, list) {
		if (hpdev->dev->ifindex == ifindex)
			return hpdev;
	}
	return NULL;
}

static inline void hpio_add_dev(struct hpio_net *hpnet, struct hpio_dev *hpdev)
{
	list_add(&hpdev->list, &hpnet->dev_list);
}

static inline void hpio_del_dev(struct hpio_net *hpnet, struct hpio_dev *hpdev)
{
	list_del(&hpdev->list);
}


/* ring operations */

static inline bool ring_empty(const struct hpio_ring *r)
{
	return (r->head == r->tail);
}

static inline bool ring_full(const struct hpio_ring *r)
{
	return (((r->head + 1) & r->mask) == r->tail);
}

static inline void ring_write_next(struct hpio_ring *r)
{
	r->head = (r->head + 1) & r->mask;
}

static inline void ring_read_next(struct hpio_ring *r)
{
	r->tail = (r->tail + 1) & r->mask;
}

static inline u32 ring_read_avail(const struct hpio_ring *r)
{
	if (r->head > r->tail) {
		return r->head - r->tail;
	} if (r->tail > r->head) {
		return r->mask - r->tail + r->head + 1;
	}

	/* ring empty */
	return 0;
}

static inline u32 ring_write_avail(const struct hpio_ring *r)
{
	if (r->tail > r->head) {
		return r->tail - r->head;
	} if (r->head > r->tail) {
		return r->mask - r->head + r->tail + 1;
	}

	/* ring empty, all slots are avaialble */
	return r->mask;
}


static void hpio_init_rx_ring(struct hpio_ring *ring, int cpu)
{
	ring->cpu = cpu;
	ring->head = 0;
	ring->tail = 0;
	ring->mask = HPIO_SLOT_NUM - 1;
}

static void hpio_destroy_rx_ring(struct hpio_ring *ring)
{
	uint32_t i, n;
	struct sk_buff *skb;

	/* free pushed skbs */

	n = ring_read_avail(ring);
	for (i = 0; i < n; i++) {
		skb = ring->skb_array[ring->tail];
		kfree_skb(skb);
		ring_read_next(ring);
	}
}

static int hpio_init_tx_ring(struct hpio_ring *ring, int cpu,
			     struct net_device *dev)
{
	uint32_t i;

	ring->cpu = cpu;
	ring->head = 0;
	ring->tail = 0;
	ring->mask = HPIO_SLOT_NUM - 1;

	for (i = 0; i < HPIO_SLOT_NUM; i++) {
		ring->skb_array[i] = __alloc_skb(HPIO_PACKET_SIZE
						 + NET_SKB_PAD,
						 GFP_NOWAIT, SKB_ALLOC_FCLONE,
						 cpu_to_node(cpu));
		if (!ring->skb_array[i])
			return -ENOMEM;

		skb_reserve(ring->skb_array[i], NET_SKB_PAD);
		ring->skb_array[i]->dev = dev;
		ring->skb_array[i]->queue_mapping = cpu;
		ring->skb_array[i]->xmit_more = 1;	/* XXX */
	}

	return 0;
}


static void hpio_destroy_tx_ring(struct hpio_ring *ring)
{
	uint32_t i;

	for (i = 0; i < HPIO_SLOT_NUM; i++)
		kfree_skb(ring->skb_array[i]);
}

/* rx register handler */

static int hpio_check_tos(struct sk_buff *skb, int tos)
{
	struct ethhdr *eth;
	struct iphdr *ip;

	eth = eth_hdr(skb);
	if (eth->h_proto == htons(ETH_P_IP)) {
		ip = (struct iphdr *)(eth + 1);
		if (ip->tos == tos)
			return 1;
	}

	return 0;
}

static struct hpio_dev *hpio_dev_get_rcu(const struct net_device *d)
{
	return rcu_dereference(d->rx_handler_data);
}

rx_handler_result_t hpio_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct hpio_dev *hpdev = hpio_dev_get_rcu(skb->dev);
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);

	if (tos_consumed && !hpio_check_tos(skb, tos_consumed)) {
		return RX_HANDLER_PASS;
	}

	if (ring_full(ring))
		goto done;

	ring->skb_array[ring->head] = skb;
	ring_write_next(ring);

	*pskb = NULL;

	return RX_HANDLER_CONSUMED;

done:
	kfree_skb(skb);
	*pskb = NULL;
	return RX_HANDLER_CONSUMED;
}



/* character device operations */

static int
hpio_start_dev(struct hpio_dev *hpdev)
{
	int ret = 0;

	rtnl_lock();
	if (netdev_is_rx_handler_busy(hpdev->dev)) {
		ret = -EBUSY;
		goto out;
	}
	netdev_rx_handler_register(hpdev->dev, hpio_handle_frame, hpdev);

out:
	rtnl_unlock();
	return 0;
}

static int
hpio_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hpio_dev *hpdev;
	struct net_device *dev;
	char devname[IFNAMSIZ];

	strncpy(devname, filp->f_path.dentry->d_name.name, IFNAMSIZ);

	dev = dev_get_by_name(&init_net, devname);	/* XXX: not init_net */
	if (!dev) {
		pr_err("net device %s not found\n", devname);
		return -ENODEV;
	}

	hpdev = hpio_find_dev(dev_net(dev), dev);
	if (!hpdev) {
		pr_err("net device %s is not registered fot hpio\n",
		       devname);
		return -ENODEV;
	}


	/* overwrite private_data when 2nd open
	 * XXX: should check pid of the process calling open().
	 * but, file->f_owner->pid is 0... how to check pid from kernel?
	 */
	filp->private_data = hpdev;

	/* start to hook rx packets */
	if ((filp->f_flags & O_ACCMODE) != O_WRONLY) {
		/* rx_handler is registered when mode is not WRONLY (read). */
		ret = hpio_start_dev(hpdev);
	}

	return ret;
}

static ssize_t
hpio_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	u32 copylen, pktlen;
	struct sk_buff *skb;
	struct hpio_hdr hdr;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);

	/* copy 1 packet */

	if (ring_empty(ring))
		return 0;

	skb = ring->skb_array[ring->tail];
	pktlen = skb->mac_len + skb->len;
	copylen = packet_copy_len(pktlen, count);

	hdr.version = HPIO_HDR_VERSION;
	hdr.hdrlen = sizeof(struct hpio_hdr)  >> 2;
	hdr.pktlen = pktlen;
	hdr.tstamp = skb_hwtstamps(skb)->hwtstamp;

	copy_to_user(buf, (char *)&hdr, sizeof(hdr));
	copy_to_user(buf + sizeof(hdr), skb_mac_header(skb), copylen);


	kfree_skb(skb);	/* should be delayed execution? */

	ring_read_next(ring);

	return copylen;
}

static ssize_t
hpio_read_iov(struct hpio_dev *hpdev, struct iov_iter *iter)
{
	ssize_t retval = 0;
	size_t count = iter->nr_segs;
	u32 copylen, pktlen, copynum, avail, i;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);
	struct hpio_hdr hdr;
	struct sk_buff *skb;

	/* copy bulk packets to user via readv systemcall.
	 * It copies 1 packet to 1 iovec. not similar to conventional readv().
	 */

	if (unlikely(iter->type != ITER_IOVEC)) {
		pr_err("unsupported iter type %d\n", iter->type);
		return -EOPNOTSUPP;
	}

	if (ring_empty(ring))
		goto out;

	avail = ring_read_avail(ring);
	copynum = (avail > count) ? count : avail;

	pr_debug("%s: count %lu, avail %u, copynum %u\n",
		 __func__, count, avail, copynum);

	for (i = 0; i < copynum; i++) {

		skb = ring->skb_array[ring->tail];
		pktlen = skb->mac_len + skb->len;
		copylen = packet_copy_len(pktlen, iter->iov[i].iov_len);

		hdr.version = HPIO_HDR_VERSION;
		hdr.hdrlen = sizeof(struct hpio_hdr) >> 2;
		hdr.pktlen = pktlen;
		hdr.tstamp = skb_hwtstamps(skb)->hwtstamp;

		copy_to_user(iter->iov[i].iov_base,
			     (char *)&hdr, sizeof(hdr));
		copy_to_user(iter->iov[i].iov_base + sizeof(hdr),
			     skb_mac_header(skb), copylen);

		kfree_skb(skb);

		retval++;
		ring_read_next(ring);
	}

	if (retval > 0)
		pr_debug("%s: ret %lu packets\n", __func__, retval);

out:
	return retval;
}

static ssize_t
hpio_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;

	return hpio_read_iov(hpdev, iter);
}


static ssize_t hpio_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	u32 copylen;
	struct sk_buff *skb, *pskb;
	struct hpio_hdr *hdr;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), tx);

	/* send 1 packet, never full */


	hdr = (struct hpio_hdr *)buf;
	if (unlikely(hdr->version != HPIO_HDR_VERSION)) {
		pr_debug("%s: invalid hpio hdr version '0x%x'\n",
			 __func__, hdr->version);
		return -EINVAL;
	}


	skb = ring->skb_array[ring->head];	/* use head as buffer */
	ring_write_next(ring);			/* protect the skb */

	if ((hdr->pktlen + sizeof(struct hpio_hdr)) > count) {
		copylen = count - sizeof(struct hpio_hdr);
	} else {
		copylen = hdr->pktlen;
	}

	skb_put(skb, copylen);
	skb_set_mac_header(skb, 0);

	copy_from_user(skb_mac_header(skb), (char *)(hdr + 1), copylen);

	pskb = skb_clone(skb, GFP_ATOMIC);
	if (!pskb)
		return -ENOMEM;


	dev_queue_xmit(pskb);

	return count;
}

static ssize_t hpio_write_iov(struct hpio_dev *hpdev, struct iov_iter *iter)
{
	int ret;
	ssize_t retval = 0;
	size_t count = iter->nr_segs;
	u32 copylen, avail, i, copynum;
	struct sk_buff *skb, **pskb;
	struct net_device *dev;
	struct netdev_queue *txq;
	struct hpio_hdr *hdr;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), tx);

	/* send bulked packets */

	dev = hpdev->dev;

	avail = ring_write_avail(ring);
	copynum = avail > count ? count : avail;


	/* first, write packets to skb ring buffers */
	for (i = 0; i < copynum; i++) {
		skb = ring->skb_array[ring->head];
		pskb = &ring->skb_tx_array[ring->head];

		hdr = (struct hpio_hdr *) iter->iov[i].iov_base;
		if (unlikely(hdr->version != HPIO_HDR_VERSION)) {
			pr_debug("%s: invalid hpio hdr version '0x%x'\n",
				 __func__, hdr->version);
			continue;
		}

		if ((hdr->pktlen + sizeof(struct hpio_hdr)) >
		    iter->iov[i].iov_len) {
			copylen = iter->iov[i].iov_len -
				sizeof(struct hpio_hdr);
		} else {
			copylen = hdr->pktlen;
		}


		*pskb = skb_get(skb);
		skb_trim(*pskb, 0);
		skb_put(*pskb, copylen);
		skb_set_mac_header(*pskb, 0);

		copy_from_user(skb_mac_header(*pskb), (char *)(hdr + 1),
			       copylen);

		ring_write_next(ring);
	}

	/* second, send queued packet XXX should be kthread workder ? */
	avail = ring_read_avail(ring);

	pr_debug("%s: read count %lu, avail %u, head %u, tail %u\n",
		 __func__, count, avail, ring->head, ring->tail);


	/* send bulked packets under once lock
	 * as same as xmit_more of pktgen_xmit() in net/core/pktgen.c
	 */

	txq = netdev_get_tx_queue(dev, ring->cpu);

	HARD_TX_LOCK(dev, txq, ring->cpu);
	local_bh_disable();

	for (i = 0; i < avail; i++) {

		skb = ring->skb_tx_array[ring->tail];

		if (unlikely(!netif_running(hpdev->dev) ||
			     !netif_carrier_ok(hpdev->dev) ||
			     netif_xmit_frozen_or_drv_stopped(txq))) {
			/* cannot xmit, free cloned skb and goto next */
			kfree_skb(skb);
			goto next;
		}

		ret = netdev_start_xmit(skb, dev, txq, avail - i - 1);

		/* TODO: implemente pkt/err counters */
		switch (ret) {
		case NETDEV_TX_BUSY :
			pr_debug("%s netdev failure\n", __func__);
			break;
		case NET_XMIT_DROP :
		case NET_XMIT_CN :
			break;
		}

		if (!dev_xmit_complete(ret)) {
			net_info_ratelimited("xmit failed, free cloned skb\n");
			kfree_skb(skb);
		} else {
			retval++;
		}

	next:
		ring_read_next(ring);
	}

	HARD_TX_UNLOCK(dev, txq);
	local_bh_enable();

	return retval;	/* retrun num of xmitted packets */
}

static ssize_t hpio_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;

	return hpio_write_iov(hpdev, iter);
}

static unsigned int hpio_poll(struct file *file, poll_table *wait)
{
	struct hpio_dev *hpdev = (struct hpio_dev *)file->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);

	poll_wait(file, &hpio_wait, wait);
	if (!ring_empty(ring))
		return POLLIN | POLLRDNORM;

	return 0;
}

static void hpio_stop_dev(struct hpio_dev *hpdev)
{
	rtnl_lock();
	netdev_rx_handler_unregister(hpdev->dev);
	rtnl_unlock();
}

static int
hpio_release(struct inode *inode, struct file *filp)
{
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;

	hpio_stop_dev(hpdev);
	filp->private_data = NULL;

	return 0;
}

static struct file_operations hpio_fops = {
	.owner		= THIS_MODULE,
	.open		= hpio_open,
	.read		= hpio_read,
	.read_iter	= hpio_read_iter,
	.write		= hpio_write,
	.write_iter	= hpio_write_iter,
	.poll		= hpio_poll,
	.release	= hpio_release,
};


/* hpio socket operations */

static inline struct hpio_sock *hpio_sk(const struct sock *sk)
{
	return (struct hpio_sock *)sk;
}

static int hpio_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct hpio_sock *hpsk;

	if (!sk) {
		pr_debug("NULL sk\n");
		return 0;
	}

	hpsk = hpio_sk(sk);
	if (hpsk->hpdev) {
		atomic_dec(&hpsk->hpdev->refcnt);
		hpio_stop_dev(hpsk->hpdev);
		hpsk->hpdev = NULL;
	}

	sock_orphan(sk);
	sk_refcnt_debug_release(sk);
	sock_put(sk);
	sock->sk = NULL;

	return 0;
}

static int hpio_sock_bind(struct socket *sock, struct sockaddr *uaddr,
			  int addrlen)
{
	int ret = 0;
	struct net *net = sock_net(sock->sk);
	struct hpio_sock *hpsk = hpio_sk(sock->sk);
	struct hpio_dev *hpdev;
	struct sockaddr_ll *sll = (struct sockaddr_ll *)uaddr;

	if (addrlen < sizeof(struct sockaddr_ll))
		return -EINVAL;

	if (sll->sll_family != AF_HPIO)
		return -EAFNOSUPPORT;

	hpdev = hpio_find_dev_by_index(net, sll->sll_ifindex);
	if (!hpdev)
		return -ENODEV;

	/* ok, start to use the device under hpio socket */
	hpsk->hpdev = hpdev;
	ret = hpio_start_dev(hpdev);
	if (ret < 0)
		goto err_out;

	atomic_inc(&hpdev->refcnt);

err_out:

	return ret;
}

static unsigned int hpio_sock_poll(struct file *file, struct socket *sock,
				   struct poll_table_struct *wait)
{
	struct hpio_sock *hpsk = hpio_sk(sock->sk);
	struct hpio_ring *ring;

	if (!hpsk->hpdev)
		return -EINVAL;

	ring = hpio_get_ring(hpsk->hpdev, smp_processor_id(), rx);

	poll_wait(file, &hpio_wait, wait);
	if (!ring_empty(ring))
		return POLLIN | POLLRDNORM;

	return 0;
}

static int hpio_sendmsg(struct socket *sock,
			struct msghdr *m, size_t total_len)
{
	struct hpio_sock *hpsk = hpio_sk(sock->sk);

	if (!hpsk->hpdev)
		return -ENODEV;

	return hpio_write_iov(hpsk->hpdev, &m->msg_iter);
}

static int hpio_recvmsg(struct socket *sock,
			struct msghdr *m, size_t total_len, int flags)
{
	struct hpio_sock *hpsk = hpio_sk(sock->sk);

	if (!hpsk->hpdev)
		return -ENODEV;

	return hpio_read_iov(hpsk->hpdev, &m->msg_iter);
}

static const struct proto_ops hpio_proto_ops = {
	.family		= PF_HPIO,
	.owner		= THIS_MODULE,
	.release	= hpio_sock_release,
	.bind		= hpio_sock_bind,
	.poll		= hpio_sock_poll,
	.sendmsg	= hpio_sendmsg,
	.recvmsg	= hpio_recvmsg,
	.mmap		= sock_no_mmap,
};

static struct proto hpio_proto = {
	.name		= "HPIO",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct hpio_sock),
};

static int hpio_sock_create(struct net *net, struct socket *sock,
			    int protocol, int kern)
{
	struct sock *sk;
	struct hpio_sock *hpsk;

	sock->ops = &hpio_proto_ops;

	sk = sk_alloc(net, PF_HPIO, GFP_KERNEL, &hpio_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	hpsk = hpio_sk(sk);
	hpsk->hpdev = NULL;	/* registered when bind() is called */

	return 0;
}

static struct net_proto_family hpio_family_ops = {
	.family	= PF_HPIO,
	.create	= hpio_sock_create,
	.owner 	= THIS_MODULE,
};


/* hpio device operations */

int init_hpio_dev(struct hpio_dev *hpdev, struct net_device *dev)
{
	int i, n, rc = 0;

	/* init hpio device structure */
	memset(hpdev, 0, sizeof(struct hpio_dev));
	snprintf(hpdev->path, 10 + IFNAMSIZ, "%s/%s", DRV_NAME, dev->name);
	hpdev->dev = dev;
	hpdev->pid = 0;
	hpdev->num_rings = num_possible_cpus();
	hpdev->mdev.minor = MISC_DYNAMIC_MINOR;
	hpdev->mdev.fops = &hpio_fops;
	hpdev->mdev.name = hpdev->path;

	/* allocate rx_rings */
	hpdev->rx_rings = kmalloc(sizeof(struct hpio_ring) * hpdev->num_rings,
				  GFP_KERNEL);
	if (!hpdev->rx_rings) {
		pr_err("failed to kmalloc rx_rings\n");
		rc = -ENOMEM;
		goto rx_rings_failed;
	}

	for (i = 0; i < hpdev->num_rings; i++) {
		hpio_init_rx_ring(&hpdev->rx_rings[i], i);
	}

	/* allocate tx_rings */
	hpdev->tx_rings = kmalloc(sizeof(struct hpio_ring) * hpdev->num_rings,
				  GFP_KERNEL);
	if (!hpdev->tx_rings) {
		pr_err("failed to kmalloc tx_rings\n");
		rc = -ENOMEM;
		goto tx_rings_failed;
	}

	for (i = 0; i < hpdev->num_rings; i++) {
		rc = hpio_init_tx_ring(&hpdev->tx_rings[i], i, dev);
		if (rc < 0) {
			pr_err("failed to kmalloc tx_ring[%u]\n", i);
			goto tx_ring_failed;
		}
	}

	/* register character device */
	rc = misc_register(&hpdev->mdev);
	if (rc < 0) {
		pr_err("failed to register misc device %s\n", hpdev->path);
		goto misc_dev_failed;
	}

	pr_info("%s registered with %d TX/RX rings each\n",
		hpdev->path, hpdev->num_rings);

	/* init refcnt for hpio_sock */
	atomic_set(&hpdev->refcnt, 0);

	return 0;


misc_dev_failed:
	i = hpdev->num_rings;

tx_ring_failed:
	for (n = 0; n < i; n++) {	/* i is num of failed tx ring */
		hpio_destroy_tx_ring(&hpdev->tx_rings[n]);
	}
	kfree(hpdev->tx_rings);

tx_rings_failed:
	kfree(hpdev->rx_rings);

rx_rings_failed:
	kfree(hpdev);

	return rc;
}


static void
destroy_hpio_dev(struct hpio_dev *hpdev)
{
	int i;

	hpdev->dev = NULL;

	misc_deregister(&hpdev->mdev);

	/* free rx rings */
	for (i = 0; i < hpdev->num_rings; i++)
		hpio_destroy_rx_ring(&hpdev->rx_rings[i]);

	kfree(hpdev->rx_rings);

	/* free tx rings */
	for (i = 0; i < hpdev->num_rings; i++)
		hpio_destroy_tx_ring(&hpdev->tx_rings[i]);

	kfree(hpdev->tx_rings);

	kfree(hpdev);
}


static __net_init int hpio_init_net(struct net *net)
{
	int rc = 0;
	struct net_device *dev;
	struct hpio_dev *hpdev;
	struct hpio_net *hpnet = net_generic(net, hpio_net_id);

	INIT_LIST_HEAD(&hpnet->dev_list);

	for_each_netdev_rcu(net, dev) {

		rtnl_lock();
		if (netdev_is_rx_handler_busy(dev)) {
			pr_info("dev %s rx_handler is already used. "
				"so, not registered to hpio\n", dev->name);
			rtnl_unlock();
			continue;
		}
		rtnl_unlock();

		hpdev = kmalloc(sizeof(struct hpio_dev), GFP_KERNEL);
		if (!hpdev)
			return -ENOMEM;

		rc = init_hpio_dev(hpdev, dev);
		if (rc < 0) {
			pr_err("failed to register %s to hpio\n", dev->name);
			goto failed;
		}

		hpio_add_dev(hpnet, hpdev);
	}

failed:
	return rc;
}

static __net_exit void hpio_exit_net(struct net *net)
{
	struct net_device *dev;
	struct hpio_dev *hpdev;
	struct hpio_net *hpnet;
	struct list_head *p, *tmp;

	hpnet = (struct hpio_net *) net_generic(net, hpio_net_id);

	list_for_each_safe(p, tmp, &hpnet->dev_list) {
		dev = hpdev->dev;
		hpdev = list_entry(p, struct hpio_dev, list);
		hpio_del_dev(hpnet, hpdev);
		destroy_hpio_dev(hpdev);
	}
}

static struct pernet_operations hpio_net_ops = {
	.init	= hpio_init_net,
	.exit	= hpio_exit_net,
	.id	= &hpio_net_id,
	.size	= sizeof(struct hpio_net),
};


static int __init hpio_init_module(void)
{
	int rc;
	pr_info("load hpio (v%s)\n", HPIO_VERSION);

	if (tos_consumed) {
		pr_info("Packets with ToS value 0x%02X are handled by hpio\n",
			tos_consumed);
	}

	rc = register_pernet_subsys(&hpio_net_ops);
	if (rc != 0) {
		pr_err("init netns failed\n");
		goto failed;
	}

	rc = proto_register(&hpio_proto, 1);
	if (rc) {
		pr_err("proto_register failed %d\n", rc);
		goto proto_register_failed;
	}

	rc = sock_register(&hpio_family_ops);
	if (rc) {
		pr_err("sock_register_failed %d\n", rc);
		goto sock_register_failed;
	}

	return 0;


sock_register_failed:
	proto_unregister(&hpio_proto);
proto_register_failed:
	unregister_pernet_subsys(&hpio_net_ops);
failed:
	return rc;
}
module_init(hpio_init_module);

static void __exit hpio_exit_module(void)
{

	pr_info("unload hpio (v%s)\n", HPIO_VERSION);

	sock_unregister(PF_HPIO);
	proto_unregister(&hpio_proto);
	unregister_pernet_subsys(&hpio_net_ops);

	return;
}
module_exit(hpio_exit_module);
