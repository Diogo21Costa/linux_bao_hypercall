// #include <linux/module.h>
// #include <linux/kernel.h>
// #include <linux/netdevice.h>
// #include <linux/if_ether.h>
// #include <linux/skbuff.h>
// #include <linux/uaccess.h>

// #define BUFFER_SIZE 65536 // Define the size of your static buffer

// static char static_buffer[BUFFER_SIZE];
// static struct net_device *netdev;
// static struct rtnl_link_stats64 stats;

// static rx_handler_result_t handle_rx(struct sk_buff **pskb)
// {
//     struct sk_buff *skb = *pskb;
//     unsigned int len = skb->len;

//     // Copy the packet data into the static buffer
//     if (len <= BUFFER_SIZE) {
//         memcpy(static_buffer, skb->data, len);
//         pr_info("Packet received and copied to static buffer\n");
//     } else {
//         pr_warn("Packet too large for static buffer\n");
//     }

//     // Pass the packet to the upper layer
//     return RX_HANDLER_PASS;
// }

// static int __init my_module_init(void)
// {
//     netdev = dev_get_by_name(&init_net, "eth0"); // Replace "eth0" with your Ethernet device name

//     if (!netdev) {
//         pr_err("Network device not found\n");
//         return -ENODEV;
//     }

//     if (netdev_rx_handler_register(netdev, handle_rx, NULL)) {
//         pr_err("Failed to register RX handler\n");
//         return -ENOMEM;
//     }

//     pr_info("Module loaded successfully\n");
//     return 0;
// }

// static void __exit my_module_exit(void)
// {
//     if (netdev) {
//         netdev_rx_handler_unregister(netdev);
//     }

//     pr_info("Module unloaded successfully\n");
// }

// module_init(my_module_init);
// module_exit(my_module_exit);

// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("Your Name");
// MODULE_DESCRIPTION("Kernel module to route Ethernet packets to a static buffer.");


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>

#define BUFFER_SIZE (2 * 1024 * 1024) // 2MB

static char *static_buffer;
static dma_addr_t dma_handle;
static struct net_device *netdev;
static struct net_device *netdev_to_handle; // Device to handle

static rx_handler_result_t handle_rx(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    unsigned int len = skb->len;

    if (len > BUFFER_SIZE) {
        pr_warn("Packet too large for static buffer\n");
        return RX_HANDLER_PASS; // Pass the packet to the upper layer
    }

    // Copy the packet data into the static buffer
    memcpy(static_buffer, skb->data, len);
    pr_info("Packet received and copied to static buffer\n");

    // Drop the packet so it is not processed by the upper layers
    return RX_HANDLER_CONSUMED;
}

static int __init my_module_init(void)
{
    // Obtain the network device
    netdev = dev_get_by_name(&init_net, "eth0"); // Replace "eth0" with your Ethernet device name

    if (!netdev) {
        pr_err("Network device not found\n");
        return -ENODEV;
    }

    // Allocate memory for the static buffer
    static_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!static_buffer) {
        pr_err("Failed to allocate memory for static buffer\n");
        dev_put(netdev);
        return -ENOMEM;
    }

    pr_info("Allocated buffer at address %p\n", static_buffer);

    // Register the RX handler
    if (netdev_rx_handler_register(netdev, handle_rx, NULL)) {
        pr_err("Failed to register RX handler\n");
        kfree(static_buffer);
        dev_put(netdev);
        return -ENOMEM;
    }

    pr_info("Module loaded successfully\n");
    return 0;
}

static void __exit my_module_exit(void)
{
    if (netdev) {
        netdev_rx_handler_unregister(netdev);
        kfree(static_buffer);
        dev_put(netdev);
    }

    pr_info("Module unloaded successfully\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to allocate a 2MB buffer and handle Ethernet packets.");
