#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/err.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <net/genetlink.h>

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#define DRV_NAME	"hpio"
#define HPIO_VERSION	"0.0.0"
MODULE_VERSION(HPIO_VERSION);
MODULE_AUTHOR("haeena.net");
MODULE_DESCRIPTION("haeena packet i/o");
MODULE_LICENSE("GPL");


#define HPIO_SLOT_SIZE	2048
#define HPIO_SLOT_NUM	1024

struct hpio_slot {
	uint16_t	pkt_len;	/* length of packet */
	uint64_t	tstamp;		/* XXX: for mgdump compatibility */
	char pkt[1];			/* packet pointer */
} __attribute__ ((__packed__));


/* packet buffer size of a slot */
#define HPIO_PACKET_SIZE \
	(HPIO_SLOT_SIZE - sizeof(struct hpio_slot) + sizeof(char))

/* slot length with actual packet */
#define HPIO_SLOT_LEN(s) \
	((s)->pkt_len + sizeof(struct hpio_slot) - sizeof(char))

/* XXX: packet length should be spearated to .h for user apps? */



#define HPIO_RING_SIZE	(HPIO_SLOT_SIZE * HPIO_SLOT_NUM)


/* XXX: will be handled by genetlink iproute2 */
static char *ifname = NULL;
module_param(ifname, charp, S_IRUGO);
MODULE_PARM_DESC(ifname, "target network device name");




/* packet buffer ring structure */
struct hpio_ring {
	uint8_t		*p;	/* malloc pointer */
	uint32_t	head;	/* write point */
	uint32_t	tail;	/* read point */
	uint32_t	mask;	/* bit mask of ring buffer */

	struct hpio_slot *slot[HPIO_SLOT_NUM];
};
#define hpio_ring_write_slot(r) (r)->slot[(r)->head]
#define hpio_ring_read_slot(r) (r)->slot[(r)->tail]


/* hpio device structure */
struct hpio_dev {
	struct list_head	list;	/* hpio->dev_list */
	struct rcu_head		rcu;

	struct net_device	*dev;	/* net device */
	struct miscdevice	mdev;	/* character device */
	char 			path[10 + IFNAMSIZ]; /* cdev path */

	uint8_t			num_rings;	/* min (cpu, queue)*/
	struct hpio_ring	*rx_rings;
	struct hpio_ring	*tx_rings;
};
#define hpio_get_ring(h, idx, di) &((h)->di##_rings[idx])


struct hpio {
	struct list_head	dev_list;	/* hpio_dev lists */
};

struct hpio hpio; /* XXX: this structure should be per namespace structure */

/* hpio global structure operations */

static inline struct hpio_dev *hpio_find_dev(struct hpio *hpio,
					     struct net_device *dev)
{
	struct hpio_dev *hpdev;

	list_for_each_entry_rcu(hpdev, &hpio->dev_list, list) {
		if (hpdev->dev == dev)
			return hpdev;
	}
	return NULL;
}

static inline void hpio_add_dev(struct hpio *hpio, struct hpio_dev *hpdev)
{
	list_add_rcu(&hpdev->list, &hpio->dev_list);
}

static inline void hpio_del_dev(struct hpio_dev *hpdev)
{
	list_del_rcu(&hpdev->list);
}


/* ring operations */

static int hpio_allocate_ring(struct hpio_ring *ring, int cpu)
{
	uint32_t i;

	ring->p = kmalloc_node(HPIO_RING_SIZE, GFP_KERNEL, cpu_to_node(cpu));
	if (!ring->p) {
		pr_err("failed to allocate ring buffer for cpu %u\n", cpu);
		return -ENOMEM;
	}

	memset(ring->p, 0, HPIO_RING_SIZE);
	ring->head = 0;
	ring->tail = 0;
	ring->mask = HPIO_SLOT_NUM - 1;

	/* assign ring->slot to actual memory address */
	for (i = 0; i < HPIO_SLOT_NUM; i++) {
		ring->slot[i] = (struct hpio_slot *)(ring->p +
						     HPIO_SLOT_SIZE * i);
	}

	pr_info("%s: ring for cpu %u, mem:%p\n", __func__, cpu, ring->p);

	return 0;
}

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
	} else {
		return r->mask - r->tail + r->head;
	}
}


/* rx register handler */

static struct hpio_dev *hpio_dev_get_rcu(const struct net_device *d)
{
	return rcu_dereference(d->rx_handler_data);
}

rx_handler_result_t hpio_handle_frame(struct sk_buff **pskb)
{
	uint32_t pktlen, copylen;
	struct sk_buff *skb = *pskb;
	struct hpio_dev *hpdev = hpio_dev_get_rcu(skb->dev);
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);
	struct hpio_slot *slot = hpio_ring_write_slot(ring);

	if (ring_full(ring))
		goto done;

	pktlen = skb->mac_len + skb->len;
	copylen = (pktlen > HPIO_PACKET_SIZE) ? HPIO_PACKET_SIZE : pktlen;
	
	slot->pkt_len = copylen;
	slot->tstamp = skb_hwtstamps(skb)->hwtstamp.tv64;
	memcpy(slot->pkt, skb_mac_header(skb), copylen);

	ring_write_next(ring);

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

	dev = dev_get_by_name(&init_net, devname);
	if (!dev) {
		pr_err("net device %s not found\n", devname);
		return -ENODEV;
	}

	hpdev = hpio_find_dev(&hpio, dev);
	if (!hpdev) {
		pr_err("net device %s is not registered fot hpio\n",
		       devname);
		return -ENODEV;
	}

	if (filp->private_data == hpdev) {
		pr_err("char dev %s is already opend\n", devname);
		return -EBUSY;
	}

	filp->private_data = hpdev;

	return 0;
}

static ssize_t
hpio_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	u32 copylen;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);
	struct hpio_slot *slot = hpio_ring_read_slot(ring);

	/* copy 1 packet */

	if (ring_empty(ring))
		return 0;

	copylen = count > HPIO_SLOT_LEN(slot) ? HPIO_SLOT_LEN(slot) : count;

	if (copy_to_user(buf, (char *)slot, copylen)) {
		pr_err("%s: copy_to_user failed\n", __func__);
		return -EFAULT;
	}

	ring_read_next(ring);

	return copylen;
}

static ssize_t
hpio_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t rc, retval = 0;
	size_t count = iter->nr_segs;
	u32 copylen, copynum, avail, i;

	struct file *filp = iocb->ki_filp;
	struct hpio_dev *hpdev = (struct hpio_dev *)filp->private_data;
	struct hpio_ring *ring = hpio_get_ring(hpdev, smp_processor_id(), rx);
	struct hpio_slot *slot;

	/* copy bulk packets to user via readv systemcall.
	 * this copy 1 packet to 1 iovce. not similar to conventional readv.
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

		slot = hpio_ring_read_slot(ring);
		copylen = iter->iov[i].iov_len > HPIO_SLOT_LEN(slot) ?
			HPIO_SLOT_LEN(slot) : iter->iov[i].iov_len;
		rc = copy_to_user(iter->iov[i].iov_base,
				  (char *)slot, copylen);

		if (rc) {
			pr_err("copy_to_user failed [%u]\n", i);
			goto out;
		}

		retval++;
		ring_read_next(ring);
	}

	if (retval > 0)
		pr_debug("%s: ret %lu packets\n", __func__, retval);

out:
	return retval;
}

static int
hpio_release(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;

	return 0;
}

static struct file_operations hpio_fops = {
	.owner		= THIS_MODULE,
	.open		= hpio_open,
	.read		= hpio_read,
	.read_iter	= hpio_read_iter,
	.release	= hpio_release,
};


/* hpio device operations */

int register_hpio_dev(struct net_device *dev)
{
	int i, n, rc = 0;
	struct hpio_dev *hpdev;

	pr_info("register %s for hpio\n", dev->name);

	if (hpio_find_dev(&hpio, dev)) {
		pr_err("net device %s is already registered for hpio\n",
		       dev->name);
		return -EBUSY;
	}

	/* allocate hpio device structure */
	hpdev = kmalloc(sizeof(struct hpio_dev), GFP_KERNEL);
	if (!hpdev) {
		pr_err("failed to kmalloc hpio_dev for %s\n", dev->name);
		rc = -ENOMEM;
		goto failed;
	}

	memset(hpdev, 0, sizeof(struct hpio_dev));
	snprintf(hpdev->path, 10 + IFNAMSIZ, "%s/%s", DRV_NAME, dev->name);
	hpdev->dev = dev;
	hpdev->mdev.minor = MISC_DYNAMIC_MINOR;
	hpdev->mdev.fops = &hpio_fops;
	hpdev->mdev.name = hpdev->path;

	/* allocate rx_rings. XXX: tx_ring is not yet */
	hpdev->rx_rings = kmalloc(sizeof(struct hpio_ring) * num_online_cpus(),
				  GFP_KERNEL);
	if (!hpdev->rx_rings) {
		pr_err("failed to kmalloc rx_rings\n");
		rc = -ENOMEM;
		goto rx_rings_failed;
	}

	hpdev->num_rings = num_online_cpus();

	for (i = 0; i < hpdev->num_rings; i++) {
		rc = hpio_allocate_ring(&hpdev->rx_rings[i], i);
		if (rc < 0)
			goto rx_ring_failed;
	}


	/* register character device */
	rc = misc_register(&hpdev->mdev);
	if (rc < 0) {
		pr_err("failed to register misc device %s\n", hpdev->path);
		goto misc_dev_failed;
	}

	/* register rx handler */
	rtnl_lock();
	rc = netdev_rx_handler_register(hpdev->dev, hpio_handle_frame, hpdev);
	rtnl_unlock();
	if (rc < 0) {
		pr_err("failed to register rx hander for %s", dev->name);
		goto rx_handler_failed;
	}

	/* save hpio_dev to hpio->dev_list */
	hpio_add_dev(&hpio, hpdev);

	return 0;


rx_handler_failed:
	misc_deregister(&hpdev->mdev);

misc_dev_failed:
	i = hpdev->num_rings;

rx_ring_failed:
	for (n = 0; n < i; n++)	/* i is failed num of cpu */
		kfree(hpdev->rx_rings[n].p);

rx_rings_failed:
	kfree(hpdev);
failed:
	return rc;
}


int
unregister_hpio_dev(struct hpio_dev *hpdev, bool lock_rtnl)
{
	int i;

	pr_info("unregister device %s from hpio\n", hpdev->path);

	hpio_del_dev(hpdev);

	if (lock_rtnl)
		rtnl_lock();

	netdev_rx_handler_unregister(hpdev->dev);

	if (lock_rtnl)
		rtnl_unlock();

	hpdev->dev = NULL;

	misc_deregister(&hpdev->mdev);

	/* free rx rings */
	for (i = 0; i < hpdev->num_rings; i++) {
		kfree(hpdev->rx_rings[i].p);
		hpdev->rx_rings[i].p = NULL;
	}

	kfree(hpdev->rx_rings);

	/* XXX: free tx rings here */

	kfree(hpdev);

	return 0;
}

static int hpio_netdev_event(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct hpio_dev *hpdev = hpio_find_dev(&hpio, dev);

	if (event == NETDEV_UNREGISTER && hpdev) {
		pr_info("net device %s is removed\n", dev->name);
		unregister_hpio_dev(hpdev, false);

		/* XXX: absolutely something wrong! however,
		 * dec refcnt is needed to avoid the race condition...
		 */
		this_cpu_dec(*dev->pcpu_refcnt);
	}

	return NOTIFY_DONE;
}

static struct notifier_block hpio_notifier_block __read_mostly = {
	.notifier_call = hpio_netdev_event,
};


static void hpio_init(void)
{
	/* init global struct hpio. shouled be integrated into 
	 * per namespace structure.
	 */

	INIT_LIST_HEAD(&hpio.dev_list);
}

static int __init hpio_init_module(void)
{
	int rc;
	struct net_device *dev;

	pr_info("hpio (v%s) is loaded\n", HPIO_VERSION);

	hpio_init();


	/* temporary until implement iproute2 */
	if (!ifname) {
		pr_err("insmod %s.ko ifname=eth0\n", DRV_NAME);
		return -EINVAL;
	}
	dev = dev_get_by_name(&init_net, ifname);
	if (!dev)
		return -ENODEV;


	rc = register_netdevice_notifier(&hpio_notifier_block);
	if (rc)
		goto notifier_failed;


	return register_hpio_dev(dev);


notifier_failed:
	return rc;
}
module_init(hpio_init_module);

static void __exit hpio_exit_module(void)
{
	struct net_device *dev;
	struct hpio_dev *hpdev;

	pr_info("hpio (v%s) is unloaded\n", HPIO_VERSION);

	dev = dev_get_by_name(&init_net, ifname);
	hpdev = hpio_find_dev(&hpio, dev);

	if (hpdev)
		unregister_hpio_dev(hpdev, true);

	unregister_netdevice_notifier(&hpio_notifier_block);

	return;
}
module_exit(hpio_exit_module);
