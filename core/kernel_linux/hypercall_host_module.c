#include <asm-generic/errno-base.h>
#include <asm/kvm_host.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include "kvm_hypercall.h"
#include "hypercall_host_module.h"
#include "hypercall.h"
MODULE_LICENSE("Dual BSD/GPL");

typedef struct {
    struct list_head list;
    hypercall_t hypercall;
} queued_hypercall_t;

typedef struct {
    struct list_head head;
    struct semaphore empty;
    spinlock_t lock;
} hypercall_queue_t;

static inline void hypercall_queue_produce(hypercall_queue_t* queue,
                                           queued_hypercall_t* new_tail) {
    unsigned long flags;
    spin_lock_irqsave(&queue->lock, flags);
    list_add_tail(&new_tail->list, &queue->head);
    spin_unlock_irqrestore(&queue->lock, flags);
    up(&queue->empty);
}

static inline queued_hypercall_t* hypercall_queue_consume(hypercall_queue_t* queue) {
    queued_hypercall_t* result;
    unsigned long flags;
    int ret;
    printk("hypercall_queue_consume\n");
    ret = down_interruptible(&queue->empty);
    if (ret  == -EINTR) {
        printk("down_interruptible was interrupted\n");
        return NULL;
    }  else if (ret != 0) {
        printk("Unknown down_interruptible error\n");
        return NULL;
    }
    spin_lock_irqsave(&queue->lock, flags);

    if (list_empty(&queue->head)) {
        /* The queue might have been emptied since the semaphore was signalled.
         */
        printk("List was empty by the time we got to it.\n");
        spin_unlock_irqrestore(&queue->lock, flags);
        return NULL;
    }

    // Remove the head.
    result = list_entry(queue->head.next, queued_hypercall_t, list);    
    list_del(&result->list);
    spin_unlock_irqrestore(&queue->lock, flags);
    return result;
}

static inline void hypercall_queue_init(hypercall_queue_t* queue) {
    INIT_LIST_HEAD(&queue->head);
    init_MUTEX_LOCKED(&queue->empty);
    spin_lock_init(&queue->lock);
}

static inline void hypercall_queue_free(hypercall_queue_t* queue) {
    /* TODO(peter): traverse the list and free everything in it. */
}

static hypercall_queue_t hypercall_queue;

static int clear_queue(hypercall_queue_t* queue) {
    unsigned long flags;
    spin_lock_irqsave(&queue->lock, flags);
    while (!list_empty(&queue->head)) {
        queued_hypercall_t* hypercall =
            list_entry(queue->head.next, queued_hypercall_t, list);    
        list_del(&hypercall->list);
        kfree(hypercall);
    }
    spin_unlock_irqrestore(&queue->lock, flags);
    return 0;
}

static int hypercall_dequeue_to_user(hypercall_t __user * user_hypercall) {
    size_t failed_bytes;
    queued_hypercall_t* queued;
    hypercall_t* result;
    
    queued = hypercall_queue_consume(&hypercall_queue);
    if (queued == NULL) {
        /* We were interrupted, so return a nop. */
        static hypercall_nop_t nop = { {HYPERCALL_NOP, sizeof(nop)} };
        result = &nop.hypercall;
    } else {
        result = &queued->hypercall;
    }

    failed_bytes = copy_to_user(user_hypercall, result, result->size);
    kfree(queued);

    if (failed_bytes == 0) {
        return 0;
    } else {
        return -EINVAL;
    }
}

static unsigned long handle_hypercall(struct kvm_vcpu* vcpu,
                                      unsigned long guest_pa,
                                      unsigned long length) {
    queued_hypercall_t* new_tail;
    int ret;


    printk("Hypercall guest memory: PA=%lx, Length=%lu\n", guest_pa, length);

    if (length > HYPERCALL_MAX_SIZE) {
        printk("Size exceeds HYPERCALL_MAX_SIZE. Not copying.\n");
        return -EINVAL;
    }

    /* Subtract the size of the hypercall_t placeholder. */
    new_tail = kmalloc(sizeof(*new_tail) - sizeof(hypercall_t) + length,
                       GFP_ATOMIC);
    if (new_tail == NULL) {
        printk("Could not allocate a new queued_hypercall_t.");
        return -ENOMEM;
    }

    ret = kvm_read_guest(vcpu->kvm, guest_pa, &new_tail->hypercall, length);
    if (ret != 0) {
        printk("Could not read guest memory.");
        kfree(new_tail);
        return -EINVAL;
    }

    printk("Queueing a hypercall: type=%d length=%lu\n",
        new_tail->hypercall.type, new_tail->hypercall.size);

    hypercall_queue_produce(&hypercall_queue, new_tail);
    return 0;
}

unsigned long hypercall_handler(
        struct kvm_vcpu* vcpu,
        unsigned long nr,
        unsigned long a0,
        unsigned long a1,
        unsigned long a2,
        unsigned long a3) {
    return handle_hypercall(vcpu, a0, a1);
}

#ifndef __USER_UNIT_TEST

static int device_major;

static int device_ioctl(struct inode* inode,
                        struct file* file,
                        unsigned int ioctl_num,
                        unsigned long ioctl_param) {
    void __user *argp = (void __user *)ioctl_param;
    switch (ioctl_num) {
    case HYPERCALL_IOCTL_DEQUEUE:
        return hypercall_dequeue_to_user((hypercall_t __user *) argp);
    case HYPERCALL_IOCTL_CLEAR:
        return clear_queue(&hypercall_queue);
    default:
        printk("Uknwown ioctl number %d.\n", ioctl_num);
        return -EINVAL;
    }
    return 0;
}

static struct file_operations fops = {
    .read = NULL,
    .write = NULL,
    .open = NULL,
    .release = NULL,
    .ioctl = device_ioctl,
};

static int hypercall_host_init(void) {
    device_major = register_chrdev(0, HYPERCALL_DEVICE_NAME, &fops);
    if (device_major < 0) {
        printk("Registering the character device failed with %d.\n",
            device_major);
        return device_major;
    }
    printk("Registered device name=%s, major=%d.\n",
        HYPERCALL_DEVICE_NAME, device_major);

    hypercall_queue_init(&hypercall_queue);
    kvm_register_hypercall_callback(hypercall_handler);
    return 0;
}

static void hypercall_host_exit(void) {
    unregister_chrdev(device_major, HYPERCALL_DEVICE_NAME);
    kvm_remove_hypercall_callback(hypercall_handler);
    hypercall_queue_free(&hypercall_queue);
}

module_init(hypercall_host_init);
module_exit(hypercall_host_exit);
#endif /* __USER_UNIT_TEST */
