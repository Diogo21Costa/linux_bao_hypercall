/**
 * TODO: licsense
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <asm/io.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/platform_device.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/mm.h>

#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
#include <linux/arm-smccc.h>
#include <asm/memory.h>
#elif CONFIG_RISCV
#include <asm/sbi.h>
#endif

#define DEV_NAME "baohypercall"
#define MAX_DEVICES 16
#define NAME_LEN 32

static dev_t bao_hypercall_devt;
struct class *cl;

struct bao_hypercall
{
    struct cdev cdev;
    struct device *dev;

    int id;
    char label[NAME_LEN];

    int hc_param0;
    int hc_param1;
    int hc_param2;
    int hc_id;
    uint64_t hc_ret;
};

#ifdef CONFIG_ARM64
static uint64_t bao_hypercall_notify(struct bao_hypercall *dev) {
    register uint64_t x0 asm("x0") = ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,
                ARM_SMCCC_SMC_64, ARM_SMCCC_OWNER_VENDOR_HYP,
                dev->hc_id);
    register uint64_t x1 asm("x1") = dev->hc_param0;
    register uint64_t x2 asm("x2") = dev->hc_param1;
    register uint64_t x3 asm("x3") = dev->hc_param2;
    

    asm volatile(
        "hvc 0\t\n"
        : "=r"(x0)
        : "r"(x0), "r"(x1), "r"(x2), "r"(x3)
    );

    return x0;
}
#elif CONFIG_ARM
static uint32_t bao_hypercall_notify(struct bao_hypercall *dev) {
    register uint32_t r0 asm("r0") = ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,
                ARM_SMCCC_SMC_32, ARM_SMCCC_OWNER_VENDOR_HYP,
                dev->hc_id);
    register uint32_t r1 asm("r1") = dev->hc_param0;
    register uint32_t r2 asm("r2") = dev->hc_param1;
    register uint32_t r3 asm("r3") = dev->hc_param2;

    asm volatile(
        "hvc #0\t\n"
        : "=r"(r0)
        : "r"(r0), "r"(r1), "r"(r2), "r"(r3)
    );

    return r0;
}
#elif CONFIG_RISCV
static uint64_t bao_hypercall_notify(struct bao_hypercall *dev) {

	struct sbiret ret =
		sbi_ecall(0x08000ba0, 1, dev->id, 0, 0, 0, 0, 0);

	return ret.error;
}
#endif

static ssize_t bao_hypercall_read_fops(struct file *filp,
                           char *buf, size_t count, loff_t *ppos)
{
    struct bao_hypercall *bao_hypercall = filp->private_data;
    char kbuf[32];
    int len;

    if(*ppos != 0)
        return 0;

    len = snprintf(kbuf, sizeof(kbuf), "%llu\n", bao_hypercall->hc_ret);

    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;

    *ppos += len;

    return len;
}

static ssize_t bao_hypercall_write_fops(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
    struct bao_hypercall *bao_hypercall = filp->private_data;
    char kbuf[256]; // Assuming the input string will not exceed 256 characters
    int hypercall_id, param0, param1, param2;
    int ret;

    if (*ppos != 0 || count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    ret = sscanf(kbuf, "%d %d %d %d", &hypercall_id, &param0, &param1, &param2);
    if (ret != 4)
        return -EINVAL;

    bao_hypercall->hc_id = hypercall_id;
    bao_hypercall->hc_param0 = param0;
    bao_hypercall->hc_param1 = param1;
    bao_hypercall->hc_param2 = param2;

    bao_hypercall->hc_ret = bao_hypercall_notify(bao_hypercall);

    *ppos += count;

    return count;
}

static int bao_hypercall_mmap_fops(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

static int bao_hypercall_open_fops(struct inode *inode, struct file *filp)
{
    struct bao_hypercall *bao_hypercall = container_of(inode->i_cdev,
                                             struct bao_hypercall, cdev);
    filp->private_data = bao_hypercall;

    kobject_get(&bao_hypercall->dev->kobj);

    return 0;
}

static int bao_hypercall_release_fops(struct inode *inode, struct file *filp)
{
    struct bao_hypercall *bao_hypercall = container_of(inode->i_cdev,
                                             struct bao_hypercall, cdev);
    filp->private_data = NULL;

    kobject_put(&bao_hypercall->dev->kobj);

    return 0;
}

static struct file_operations bao_hypercall_fops = {
    .owner = THIS_MODULE,
    .read = bao_hypercall_read_fops,
    .write = bao_hypercall_write_fops,
    .mmap = bao_hypercall_mmap_fops,
    .open = bao_hypercall_open_fops,
    .release = bao_hypercall_release_fops
};

int bao_hypercall_register(struct platform_device *pdev)
{
    int ret = 0;
    struct device *dev = &(pdev->dev);
    struct device_node *np = dev->of_node;
    struct module *owner = THIS_MODULE;
    // struct resource *r;
    dev_t devt;

    int id = -1;
    struct bao_hypercall *bao;

    of_property_read_u32(np, "id", &id);
    if (id >= MAX_DEVICES) {
        dev_err(&pdev->dev,"invalid id %d\n", id);
        ret = -EINVAL;
        goto err_cdev;
    }

    bao = devm_kzalloc(&pdev->dev, sizeof(struct bao_hypercall), GFP_KERNEL);
    if(bao == NULL) {
        ret = -ENOMEM;
        goto err_cdev;
    }
    snprintf(bao->label, NAME_LEN, "%s%d", DEV_NAME, id);
    bao->id = id;

    cdev_init(&bao->cdev, &bao_hypercall_fops);
    bao->cdev.owner = owner;

    devt = MKDEV(MAJOR(bao_hypercall_devt), id);
    ret = cdev_add(&bao->cdev, devt, 1);
    if (ret) {
        goto err_cdev;
    }

    bao->dev = device_create(cl, &pdev->dev, devt, bao, bao->label);
    if (IS_ERR(bao->dev)) {
        ret = PTR_ERR(bao->dev);
        goto err_cdev;
    }
    dev_set_drvdata(bao->dev, bao);

    return 0;

err_cdev:
    cdev_del(&bao->cdev);

    dev_err(&pdev->dev,"failed initialization\n");
    return ret;
}

static int bao_hypercall_unregister(struct platform_device *pdev)
{
    /* TODO */
    return 0;
}

static const struct of_device_id of_bao_hypercall_match[] = {
    {
        .compatible = "bao,hypercall",
    },
    {/* sentinel */}};
MODULE_DEVICE_TABLE(of, of_bao_hypercall_match);

static struct platform_driver bao_hypercall_driver = {
    .probe = bao_hypercall_register,
    .remove = bao_hypercall_unregister,
    .driver = {
        .name = DEV_NAME,
        .of_match_table = of_bao_hypercall_match,
    },
};

static int __init bao_hypercall_init(void)
{
    int ret;

    if ((cl = class_create(THIS_MODULE, DEV_NAME)) == NULL) {
        ret = -1;
        pr_err("unable to class_create " DEV_NAME " device\n");
        return ret;
    }

    ret = alloc_chrdev_region(&bao_hypercall_devt, 0, MAX_DEVICES, DEV_NAME);
    if (ret < 0) {
        pr_err("unable to alloc_chrdev_region " DEV_NAME " device\n");
        return ret;
    }

    return platform_driver_register(&bao_hypercall_driver);
}

static void __exit bao_hypercall_exit(void)
{
    platform_driver_unregister(&bao_hypercall_driver);
    unregister_chrdev(bao_hypercall_devt, DEV_NAME);
    class_destroy(cl);
}

module_init(bao_hypercall_init);
module_exit(bao_hypercall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Cerdeira");
MODULE_AUTHOR("José Martins");
MODULE_AUTHOR("Diogo Costa");
MODULE_DESCRIPTION("bao hypercall sample driver");
