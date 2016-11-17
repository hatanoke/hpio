#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/err.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/pid.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>
#include <net/net_namespace.h>

#include "hpio.h"

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#define DRV_NAME	"hpio"
#define HPIO_VERSION	"0.0.0"
MODULE_VERSION(HPIO_VERSION);
MODULE_AUTHOR("haeena.net");
MODULE_DESCRIPTION("haeena packet i/o");
MODULE_LICENSE("GPL");



#define packet_copy_len(pktlen, buflen) \
	buflen > pktlen + sizeof(struct hpio_hdr) ? \
	pktlen : buflen - sizeof(struct hpio_hdr)


/* packet buffer ring structure */
struct hpio_ring {
	uint32_t	head;	/* write point */
	uint32_t	tail;	/* read point */
	uint32_t	mask;	/* bit mask of ring buffer */

	struct sk_buff *skb_array[HPIO_SLOT_NUM];
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
};
#define hpio_get_ring(h, idx, di) &((h)->di##_rings[idx])


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
		return r->mask - r->tail + r->head;
	}

	/* ring empty */
	return 0;
}

static inline u32 ring_write_avail(const struct hpio_ring *r)
{
	if (r->tail > r->head) {
		return r->tail - r->head;
	} if (r->head > r->tail) {
		return r->mask - r->head + r->tail;
	}

	/* ring empty, all slots are avaialble */
	return r->mask;
}


static void hpio_init_rx_ring(struct hpio_ring *ring)
{
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

	ring->head = 0;
	ring->tail = 0;
	ring->mask = HPIO_SLOT_NUM - 1;

	for (i = 0; i < HPIO_SLOT_NUM; i++) {
		ring->skb_array[i] = __alloc_skb(HPIO_PACKET_SIZE,
						 GFP_KERNEL, SKB_ALLOC_FCLONE,
						 cpu_to_node(cpu));
		if (!ring->skb_array[i])
			return -ENOMEM;

		ring->skb_array[i]->dev = dev;
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

static struct hpio_dev *hpio_dev_get_rcu(const struct net_device *d)
{
	return rcu_dereference(d->rx_handler_data);
}

rx_handler_result_t hpio_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct hpio_dev *hpdev = hpio_dev_get_rcu(skb->dev);
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);

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
hpio_open(struct inode *inode, struct file *filp)
{
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
		rtnl_lock();
		if (!netdev_is_rx_handler_busy(dev)) {
			netdev_rx_handler_register(dev, hpio_handle_frame,
						   hpdev);
		}
		rtnl_unlock();
	}

	return 0;
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

	hdr.pktlen = pktlen;
	hdr.tstamp = skb_hwtstamps(skb)->hwtstamp.tv64;

	copy_to_user(buf, (char *)&hdr, sizeof(hdr));
	copy_to_user(buf + sizeof(hdr), skb_mac_header(skb), copylen);


	kfree_skb(skb);	/* should be delayed execution? */

	ring_read_next(ring);

	return copylen;
}

static ssize_t
hpio_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t retval = 0;
	size_t count = iter->nr_segs;
	u32 copylen, pktlen, copynum, avail, i;

	struct file *filp = iocb->ki_filp;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
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

		hdr.pktlen = pktlen;
		hdr.tstamp = skb_hwtstamps(skb)->hwtstamp.tv64;

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

static ssize_t hpio_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	u32 copylen;
	struct sk_buff *skb, *pskb;
	struct hpio_hdr *hdr;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), tx);

	/* send 1 packet, never full */

	skb = ring->skb_array[ring->head];	/* use head as buffer */
	ring_write_next(ring);			/* protect the skb */

	hdr = (struct hpio_hdr *)buf;

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

static ssize_t hpio_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t retval = 0;
	size_t count = iter->nr_segs;
	u32 copylen, avail, i, copynum;
	struct file *filp = iocb->ki_filp;
	struct sk_buff *skb, *pskb;
	struct hpio_hdr *hdr;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), tx);

	/* send bulked packets */

	avail = ring_write_avail(ring);
	copynum = avail > count ? count : avail;

	/* first, write packets to skb ring buffers */
	for (i = 0; i < copynum; i++) {
		skb = ring->skb_array[ring->head];

		hdr = (struct hpio_hdr *) iter->iov[i].iov_base;

		if ((hdr->pktlen + sizeof(struct hpio_hdr)) >
		    iter->iov[i].iov_len) {
			copylen = iter->iov[i].iov_len -
				sizeof(struct hpio_hdr);
		} else {
			copylen = hdr->pktlen;
		}

		skb_put(skb, copylen);
		skb_set_mac_header(skb, 0);

		copy_from_user(skb_mac_header(skb), (char *)(hdr + 1),
			       copylen);

		ring_write_next(ring);
	}

	/* second, send queued packet XXX should be kthread workder ? */
	avail = ring_read_avail(ring);

	pr_debug("%s: read count %lu, avail %u, head %u, tail %u\n",
		 __func__, count, avail, ring->head, ring->tail);

	for (i = 0; i < avail; i++) {

		if (unlikely(!netif_running(hpdev->dev) ||
			     !netif_carrier_ok(hpdev->dev))) {
			goto next;
		}

		skb = ring->skb_array[ring->tail];
		pskb = skb_clone(skb, GFP_ATOMIC);
		dev_queue_xmit(pskb);

		retval++;

	next:
		ring_read_next(ring);
	}

	return retval;	/* retrun num of xmitted packets */
}

static int
hpio_release(struct inode *inode, struct file *filp)
{
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;

	rtnl_lock();
	netdev_rx_handler_unregister(hpdev->dev);
	rtnl_unlock();

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
	.release	= hpio_release,
};


/* hpio device operations */

int init_hpio_dev(struct hpio_dev *hpdev, struct net_device *dev)
{
	int i, n, rc = 0;

	pr_info("register device %s to hpio\n", dev->name);

	/* init hpio device structure */
	memset(hpdev, 0, sizeof(struct hpio_dev));
	snprintf(hpdev->path, 10 + IFNAMSIZ, "%s/%s", DRV_NAME, dev->name);
	hpdev->dev = dev;
	hpdev->pid = 0;
	hpdev->num_rings = num_online_cpus();
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
		hpio_init_rx_ring(&hpdev->rx_rings[i]);
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

	rc = register_pernet_subsys(&hpio_net_ops);
	if (rc != 0) {
		pr_err("init netns failed\n");
		goto failed;
	}

	return 0;

failed:
	return rc;
}
module_init(hpio_init_module);

static void __exit hpio_exit_module(void)
{

	pr_info("unload hpio (v%s)\n", HPIO_VERSION);

	unregister_pernet_subsys(&hpio_net_ops);

	return;
}
module_exit(hpio_exit_module);
