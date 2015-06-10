/*
 *  linux/drivers/block/abuse.c
 *
 *  Written by Zachary Amsden, 7/23/2009
 *
 *  This was heavily stolen from pieces of the loopback, network block device,
 *  and parts of FUSE.  Since then it has grown antlers and had several new
 *  limbs grafted onto it, even some of the intenal organs have been replaced.
 *  Please forgive the comments and the obvious uprooting of kernel interfaces.
 *
 *  I believe the module is named appropriately.
 *
 *  The point of this driver is to allow /user-space/ drivers for kernel block
 *  devices.  Yes, it's a strange concept.  However, it's also incredibly
 *  useful.  I would not recommend trying to swap on these devices, unless you
 *  can prove that case deadlock free.
 *
 * Copyright (c) 2009 by Zachary Amsden.  Redistribution of this file is
 * permitted under the GNU General Public License.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/buffer_head.h>		/* for invalidate_bdev() */
#include <linux/cdev.h>
#include <linux/poll.h>
#include "abuse.h"

#include <asm/uaccess.h>

static LIST_HEAD(abuse_devices);
static DEFINE_MUTEX(abuse_devices_mutex);
static DEFINE_IDR(abuse_index_idr);
static struct class *abuse_class;
static int max_part;
static int num_minors;
static int dev_shift;

static struct abuse_device *abuse_alloc(int i);
static struct abuse_device *abuse_init_one(int i);

static struct abuse_device *abuse_get_dev(int dev)
{
	struct abuse_device *ab = NULL;

	mutex_lock(&abuse_devices_mutex);
	list_for_each_entry(ab, &abuse_devices, ab_list)
		if (ab->ab_number == dev)
			break;
	mutex_unlock(&abuse_devices_mutex);
	return ab;
}

/*
 * Add bio to back of pending list
 */

static void abuse_flush_req(struct abuse_device *ab)
{
	//struct bio *bio, *next;

	/* spin_lock_irq(&ab->ab_lock); */
	/* bio = ab->ab_bio; */
	/* ab->ab_biotail = ab->ab_bio = NULL; */
	/* ab->ab_queue_size = 0; */
	/* spin_unlock_irq(&ab->ab_lock); */

	/* while (bio) { */
	/* 	next = bio->bi_next; */
	/* 	bio->bi_next = NULL; */
	/* 	bio_io_error(bio); */
	/* 	bio = next; */
	/* } */
}

static inline int is_abuse_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;

	return i && S_ISBLK(i->i_mode) && MAJOR(i->i_rdev) == ABUSE_MAJOR;
}

static int abuse_reset(struct abuse_device *ab)
{
	if (!ab->ab_disk->queue)
		return -EINVAL;

	abuse_flush_req(ab);
	ab->ab_flags = 0;
	ab->ab_errors = 0;
	ab->ab_blocksize = 0;
	ab->ab_size = 0;
	ab->ab_max_queue = 0;
	set_capacity(ab->ab_disk, 0);
	if (ab->ab_device) {
		bd_set_size(ab->ab_device, 0);
		invalidate_bdev(ab->ab_device);
		if (max_part > 0)
			ioctl_by_bdev(ab->ab_device, BLKRRPART, 0);
		blkdev_put(ab->ab_device, FMODE_READ);
		ab->ab_device = NULL;
		module_put(THIS_MODULE);
	}
	return 0;
}

static int
abuse_set_status_int(struct abuse_device *ab, struct block_device *bdev,
	const struct abuse_info *info)
{
	sector_t size = (sector_t)(info->ab_size >> 9);
	loff_t blocks;
	int err;

	if (unlikely((loff_t)size != size))
		return -EFBIG;

	if (unlikely(info->ab_blocksize == 0))
		return -EINVAL;

	blocks = info->ab_size / info->ab_blocksize;
	if (unlikely(info->ab_blocksize * blocks != info->ab_size))
		return -EINVAL;

	if (unlikely(bdev)) {
		if (bdev != ab->ab_device)
			return -EBUSY;
		if (!(ab->ab_flags & ABUSE_FLAGS_RECONNECT))
			return -EINVAL;

		/*
		 * Don't allow these to change on a reconnect.
		 * We do allow changing the max queue size and
		 * the RO flag.
		 */
		if (ab->ab_size != info->ab_size ||
		    ab->ab_blocksize != info->ab_blocksize ||
		    info->ab_max_queue > ab->ab_queue_size)
		    	return -EINVAL;
	} else {
		bdev = bdget_disk(ab->ab_disk, 0);
		if (IS_ERR(bdev)) {
			err = PTR_ERR(bdev);
			return err;
		}
		err = blkdev_get(bdev, FMODE_READ, NULL);
		if (err) {
			bdput(bdev);
			return err;
		}
		__module_get(THIS_MODULE);
	}

	ab->ab_device = bdev;
	ab->ab_queue->queuedata = ab;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, ab->ab_queue);

	ab->ab_size = info->ab_size;
	ab->ab_flags = (info->ab_flags & ABUSE_FLAGS_READ_ONLY);
	ab->ab_blocksize = info->ab_blocksize;
	ab->ab_max_queue = info->ab_max_queue;

	set_capacity(ab->ab_disk, size);
	set_device_ro(bdev, (ab->ab_flags & ABUSE_FLAGS_READ_ONLY) != 0);
	set_capacity(ab->ab_disk, size);
	bd_set_size(bdev, size << 9);
	set_blocksize(bdev, ab->ab_blocksize);
	if (max_part > 0)
		ioctl_by_bdev(bdev, BLKRRPART, 0);

	return 0;
}

static int
abuse_get_status_int(struct abuse_device *ab, struct abuse_info *info)
{
	memset(info, 0, sizeof(*info));
	info->ab_size = ab->ab_size;
	info->ab_number = ab->ab_number;
	info->ab_flags = ab->ab_flags;
	info->ab_blocksize = ab->ab_blocksize;
	info->ab_max_queue = ab->ab_max_queue;
	info->ab_queue_size = ab->ab_queue_size;
	info->ab_errors = ab->ab_errors;
	info->ab_max_vecs = BIO_MAX_PAGES;
	return 0;
}

static int
abuse_set_status(struct abuse_device *ab, struct block_device *bdev,
	const struct abuse_info __user *arg)
{
	struct abuse_info info;

	if (copy_from_user(&info, arg, sizeof (struct abuse_info)))
		return -EFAULT;
	return abuse_set_status_int(ab, bdev, &info);
}

static int
abuse_get_status(struct abuse_device *ab, struct block_device *bdev,
	struct abuse_info __user *arg)
{
	struct abuse_info info;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = abuse_get_status_int(ab, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int abuse_get_req(struct abuse_device *ab, struct abuse_xfr_hdr __user *arg)
{
	struct abuse_xfr_hdr xfr;
	struct ab_req *req = NULL;

	if (!arg)
		return -EINVAL;
	if (!ab)
		return -ENODEV;

	if (copy_from_user(&xfr, arg, sizeof (struct abuse_xfr_hdr)))
		return -EFAULT;

	spin_lock_irq(&ab->ab_lock);
	req = list_first_entry_or_null(&ab->ab_reqlist, struct ab_req, list);
	if (req) {
		struct req_iterator iter;
		struct bio_vec bvec;
		int i = 0;

		list_move_tail(&req->list, &ab->ab_reqlist);
		spin_unlock_irq(&ab->ab_lock);

		xfr.ab_id = (__u64)req;
		xfr.ab_command = rq_data_dir(req->rq);
		xfr.ab_sector = blk_rq_pos(req->rq);
		rq_for_each_segment(bvec, req->rq, iter) {
			ab->ab_xfer[i].ab_len = bvec.bv_len;
			ab->ab_xfer[i].ab_offset = bvec.bv_offset;
			++i;
		}
		xfr.ab_vec_count = req->vec_cnt = i;
	} else {
		spin_unlock_irq(&ab->ab_lock);

		xfr.ab_transfer_address = 0;
		xfr.ab_vec_count = 0;
	}

	if (copy_to_user(arg, &xfr, sizeof(xfr)))
		return -EFAULT;
	if (xfr.ab_transfer_address &&
		copy_to_user((__user void *)xfr.ab_transfer_address, ab->ab_xfer,
			     xfr.ab_vec_count * sizeof(ab->ab_xfer[0])))
		return -EFAULT;

	return req ? 0 : -ENOMSG;
}

static struct ab_req *abuse_find_req(struct abuse_device *ab, __u64 id)
{
	struct ab_req *req = NULL;
	list_for_each_entry(req, &ab->ab_reqlist, list) {
		if ((__u64)req == id)
			return req;
	}
	return NULL;
}

static inline void abuse_add_req(struct abuse_device *ab, struct ab_req *req)
{
	spin_lock_irq(&ab->ab_lock);
	list_add_tail(&req->list, &ab->ab_reqlist);
	spin_unlock_irq(&ab->ab_lock);
}

static int abuse_put_req(struct abuse_device *ab, struct abuse_xfr_hdr __user *arg)
{
	struct abuse_xfr_hdr xfr;
	struct ab_req *req = NULL;
	struct req_iterator iter;
	struct bio_vec bvec;
	int i = 0;
	unsigned long flags;

	if (!arg)
		return -EINVAL;
	if (!ab)
		return -ENODEV;

	if (copy_from_user(&xfr, arg, sizeof (struct abuse_xfr_hdr)))
		return -EFAULT;

	/*
	 * Handle catastrophes first.  Do this by giving them catnip.
	 */
	if (unlikely(xfr.ab_result == ABUSE_RESULT_DEVICE_FAILURE)) {
		abuse_flush_req(ab);
		return 0;
	}

	/*
	 * Look up the dang thing to make sure the user is telling us
	 * they've actually completed some work.  It's very doubtful.
	 */
	spin_lock_irq(&ab->ab_lock);
	req = abuse_find_req(ab, xfr.ab_id);
	if (req) {
		list_del(&req->list);
	} else {
		spin_unlock_irq(&ab->ab_lock);
		return -ENOMSG;
	}
	spin_unlock_irq(&ab->ab_lock);

	/*
	 * This isn't just arbitrary anal-retentiveness.  Userspace will
	 * obviously crash and burn, and so we check all fields as stringently
	 * as possible to provide some protection against the case when we
	 * re-use the same bio and some user-tarded program tries to complete
	 * an historical event.  Better prophylactics are possible, but crazy.
	 */
	if (blk_rq_pos(req->rq) != xfr.ab_sector ||
	    rq_data_dir(req->rq) != xfr.ab_command) {
		abuse_add_req(ab, req);
		return -EINVAL;
	}

	/*
	 * Now handle individual failures that don't affect other I/Os.
	 */
	if (unlikely(xfr.ab_result == ABUSE_RESULT_MEDIA_FAILURE)) {
		blk_mq_end_request(req->rq, -EIO);
		return 0;
	}

	/*
	 * We've now stolen the bio off the queue.  This is stupid if we don't
	 * complete it.  But we don't want to hold the spinlock while doing I/O
	 * from the user component.  If userspace bugs out and crashes, as is
	 * to be expected from a userspace program, so be it.  The bio can
	 * always be cancelled by a sane actor when we put it back.
	 */
	if (copy_from_user(ab->ab_xfer, (__user void *)xfr.ab_transfer_address,
			     req->vec_cnt * sizeof(ab->ab_xfer[0]))) {
		abuse_add_req(ab, req);
		return -EFAULT;
	}

	/*
	 * You made it this far?  It's time for the third movement.
	 */
	rq_for_each_segment(bvec, req->rq, iter) {
		int ret;
		void *kaddr = kmap(bvec.bv_page);

		if (rq_data_dir(req->rq) != WRITE)
			ret = copy_from_user(kaddr + bvec.bv_offset,
					     (void *)ab->ab_xfer[i].ab_address,
					     bvec.bv_len);
		else
			ret = copy_to_user((void *)ab->ab_xfer[i].ab_address,
					   kaddr + bvec.bv_offset, bvec.bv_len);

		kunmap(bvec.bv_page);
		if (ret != 0) {
			/* Wise, up sucker! (PWEI RULEZ) */
			abuse_add_req(ab, req);
			return -EFAULT;
		}
		++i;
	}

	/* Well, you did it.  Congraulations, you get a pony. */
	pr_info("rq->q: %p\n", req->rq->q);
	spin_lock_irqsave(req->rq->q->queue_lock, flags);
	blk_mq_end_request(req->rq, 0);
	spin_unlock_irqrestore(req->rq->q->queue_lock, flags);

	return 0;
}

static long abctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct abuse_device *ab = filp->private_data;
	struct abuse_device *new;
	int err;

	if (!ab || !ab->ab_disk)
		return -ENODEV;

	mutex_lock(&ab->ab_ctl_mutex);
	switch (cmd) {
	case ABUSE_GET_STATUS:
		err = abuse_get_status(ab, ab->ab_device,
				       (struct abuse_info __user *) arg);
		break;
	case ABUSE_SET_STATUS:
		err = abuse_set_status(ab, ab->ab_device,
				       (struct abuse_info __user *) arg);
		break;
	case ABUSE_RESET:
		err = abuse_reset(ab);
		break;
	case ABUSE_GET_REQ:
		err = abuse_get_req(ab, (struct abuse_xfr_hdr __user *) arg);
		break;
	case ABUSE_PUT_REQ:
		err = abuse_put_req(ab, (struct abuse_xfr_hdr __user *) arg);
		break;
	case ABUSE_CTL_ADD:
		new = abuse_alloc(arg);
		if (new) {
			add_disk(new->ab_disk);
			list_add_tail(&new->ab_list, &abuse_devices);
			err = new->ab_number;
		} else {
			err = -EEXIST; /* FIXME: better error handling */
		}
		break;
	default:
		err = -EINVAL;
	}
	mutex_unlock(&ab->ab_ctl_mutex);
	return err;
}

static unsigned int abctl_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct abuse_device *ab = filp->private_data;

	poll_wait(filp, &ab->ab_event, wait);

	/*
	 * The comment in asm-generic/poll.h says of these nonstandard values,
	 * 'Check them!'.  Thus we use POLLMSG to force the user to check it.
	 */
	mask = (list_empty(&ab->ab_reqlist)) ? 0 : POLLMSG;

	return mask;
}

static int abctl_open(struct inode *inode, struct file *filp)
{
	struct abuse_device *ab;

	ab = abuse_get_dev(iminor(inode));
	if (!ab)
		return -ENODEV;

	filp->private_data = ab;
	return 0;
}

static int abctl_release(struct inode *inode, struct file *filp)
{
	struct abuse_device *ab = filp->private_data;
	if (!ab)
		return -ENODEV;

	return 0;
}

static int ab_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ab_release(struct gendisk *disk, fmode_t mode)
{
	return;
}

static struct block_device_operations ab_fops = {
	.owner =	THIS_MODULE,
	.open =		ab_open,
	.release =	ab_release,
};

static struct file_operations abctl_fops = {
	.owner =	THIS_MODULE,
	.open =		abctl_open,
	.release =	abctl_release,
	.unlocked_ioctl =	abctl_ioctl,
	.poll =		abctl_poll,
};

/*
 * And now the modules code and kernel interface.
 */
static int max_abuse;
module_param(max_abuse, int, 0);
MODULE_PARM_DESC(max_abuse, "Maximum number of abuse devices");
module_param(max_part, int, 0);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per abuse device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(ABUSE_MAJOR);

static int abuse_init_request(void *data, struct request *rq,
		unsigned int hctx_idx, unsigned int request_idx,
		unsigned int numa_node)
{
	struct ab_req *req = blk_mq_rq_to_pdu(rq);

	req->rq = rq;

	return 0;
}

static int abuse_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct ab_req *req = blk_mq_rq_to_pdu(bd->rq);
	struct abuse_device *ab = req->rq->q->queuedata;

	blk_mq_start_request(bd->rq);

	spin_lock_irq(&ab->ab_lock);
	list_add_tail(&req->list, &ab->ab_reqlist);
	wake_up(&ab->ab_event);
	spin_unlock_irq(&ab->ab_lock);

	pr_info("abuse_queue_rq rq->q: %p\n", req->rq->q);

	return BLK_MQ_RQ_QUEUE_OK;;
}

static struct blk_mq_ops abuse_mq_ops = {
	.queue_rq       = abuse_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_request	= abuse_init_request,
};

/* FIXME: error propagation */
static struct abuse_device *abuse_alloc(int i)
{
	struct abuse_device *ab;
	struct gendisk *disk;
	struct cdev *cdev;
	int err;

	ab = kzalloc(sizeof(*ab), GFP_KERNEL);
	if (!ab)
		goto out;

	if (i >= 0) {
		err = idr_alloc(&abuse_index_idr, ab, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&abuse_index_idr, ab, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_free_dev;
	i = err;

	ab->tag_set.ops = &abuse_mq_ops;
	ab->tag_set.nr_hw_queues = 1;
	ab->tag_set.queue_depth = 128;
	ab->tag_set.numa_node = NUMA_NO_NODE;
	ab->tag_set.cmd_size = sizeof(struct ab_req);
	ab->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	ab->tag_set.driver_data = ab;

	err = blk_mq_alloc_tag_set(&ab->tag_set);
	if (err)
		goto out_free_idr;

	ab->ab_queue = blk_mq_init_queue(&ab->tag_set);
	if (IS_ERR_OR_NULL(ab->ab_queue))
		goto out_cleanup_tags;
	ab->ab_queue->queuedata = ab;

	disk = ab->ab_disk = alloc_disk(num_minors);
	if (!disk)
		goto out_free_queue;

	disk->major		= ABUSE_MAJOR;
	disk->first_minor	= i << dev_shift;
	disk->fops		= &ab_fops;
	disk->private_data	= ab;
	disk->queue		= ab->ab_queue;
	sprintf(disk->disk_name, "abuse%d", i);

	cdev = ab->ab_cdev = cdev_alloc();
	if (!cdev)
		goto out_free_disk;

	cdev->owner = THIS_MODULE;
	cdev->ops = &abctl_fops;

	if (cdev_add(ab->ab_cdev, MKDEV(ABUSECTL_MAJOR, i), 1) != 0)
		goto out_free_cdev;

	mutex_init(&ab->ab_ctl_mutex);
	ab->ab_number		= i;
	init_waitqueue_head(&ab->ab_event);
	spin_lock_init(&ab->ab_lock);
	INIT_LIST_HEAD(&ab->ab_reqlist);

	return ab;

out_free_cdev:
	cdev_del(ab->ab_cdev);
out_free_disk:
	put_disk(ab->ab_disk);
out_free_queue:
	blk_cleanup_queue(ab->ab_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&ab->tag_set);
out_free_idr:
	idr_remove(&abuse_index_idr, i);
out_free_dev:
	kfree(ab);
out:
	return NULL;
}

static void abuse_free(struct abuse_device *ab)
{
	blk_cleanup_queue(ab->ab_queue);
	device_destroy(abuse_class, MKDEV(ABUSECTL_MAJOR, ab->ab_number));
	cdev_del(ab->ab_cdev);
	put_disk(ab->ab_disk);
	list_del(&ab->ab_list);
	idr_remove(&abuse_index_idr, ab->ab_number);
	kfree(ab);
}

static struct abuse_device *abuse_init_one(int i)
{
	struct abuse_device *ab;

	list_for_each_entry(ab, &abuse_devices, ab_list)
		if (ab->ab_number == i)
			return ab;

	ab = abuse_alloc(i);
	if (ab) {
		add_disk(ab->ab_disk);
		list_add_tail(&ab->ab_list, &abuse_devices);
	}
	return ab;
}

static void abuse_del_one(struct abuse_device *ab)
{
	del_gendisk(ab->ab_disk);
	abuse_free(ab);
}

static struct kobject *abuse_probe(dev_t dev, int *part, void *data)
{
	struct abuse_device *ab;
	struct kobject *kobj;

	mutex_lock(&abuse_devices_mutex);
	ab = abuse_init_one(dev & MINORMASK);
	kobj = ab ? get_disk(ab->ab_disk) : ERR_PTR(-ENOMEM);
	mutex_unlock(&abuse_devices_mutex);

	*part = 0;
	return kobj;
}

static int __init abuse_init(void)
{
	int i, nr, err;
	unsigned long range;
	struct abuse_device *ab, *next;
	struct device *device;

	/*
	 * abuse module has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 *
	 * (1) if max_abuse is specified, create that many upfront, and this
	 *     also becomes a hard limit.  Cross it and divorce is likely.
	 * (2) if max_abuse is not specified, create 8 abuse device on module
	 *     load, user can further extend abuse device by create dev node
	 *     themselves and have kernel automatically instantiate actual
	 *     device on-demand.
	 */

	dev_shift = 0;
	if (max_part > 0)
		dev_shift = fls(max_part);
	num_minors = 1 << dev_shift;

	if (max_abuse > 1UL << (MINORBITS - dev_shift))
		return -EINVAL;

	if (max_abuse) {
		nr = max_abuse;
		range = max_abuse;
	} else {
		nr = 8;
		range = 1UL << (MINORBITS - dev_shift);
	}

	err = -EIO;
	if (register_blkdev(ABUSE_MAJOR, "abuse")) {
		printk("abuse: register_blkdev failed!\n");
		return err;
	}

	err = register_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range, "abuse");
	if (err) {
		printk("abuse: register_chrdev_region failed!\n");
		goto unregister_blk;
	}

	abuse_class = class_create(THIS_MODULE, "abuse");
	if (IS_ERR(abuse_class)) {
		err = PTR_ERR(abuse_class);
		goto unregister_chr;
	}

	err = -ENOMEM;
	for (i = 0; i < nr; i++) {
		ab = abuse_alloc(i);
		if (!ab) {
			printk(KERN_INFO "abuse: out of memory\n");
			goto free_devices;
		}
		list_add_tail(&ab->ab_list, &abuse_devices);
	}

	/* point of no return */

	list_for_each_entry(ab, &abuse_devices, ab_list)
		add_disk(ab->ab_disk);

	blk_register_region(MKDEV(ABUSE_MAJOR, 0), range,
				  THIS_MODULE, abuse_probe, NULL, NULL);

	/* add control device */
	device = device_create(abuse_class, NULL, MKDEV(ABUSECTL_MAJOR, 0), ab, "abctl");
	if (IS_ERR(device)) {
		printk(KERN_ERR "abuse_init: abctl creation failed\n");
		goto free_devices; /* FIXME: confirm error handling */
	}

	printk(KERN_INFO "abuse: module loaded\n");
	return 0;

free_devices:
	list_for_each_entry_safe(ab, next, &abuse_devices, ab_list)
		abuse_free(ab);
unregister_chr:
	unregister_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range);
unregister_blk:
	unregister_blkdev(ABUSE_MAJOR, "abuse");
	return err;
}

static void __exit abuse_exit(void)
{
	unsigned long range;
	struct abuse_device *ab, *next;

	range = max_abuse ? max_abuse :  1UL << (MINORBITS - dev_shift);

	list_for_each_entry_safe(ab, next, &abuse_devices, ab_list)
		abuse_del_one(ab);
	idr_destroy(&abuse_index_idr);
	class_destroy(abuse_class);
	blk_unregister_region(MKDEV(ABUSE_MAJOR, 0), range);
	unregister_chrdev_region(MKDEV(ABUSECTL_MAJOR, 0), range);
	unregister_blkdev(ABUSE_MAJOR, "abuse");
}

module_init(abuse_init);
module_exit(abuse_exit);

#ifndef MODULE
static int __init max_abuse_setup(char *str)
{
	max_abuse = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_abuse=", max_abuse_setup);
#endif
