#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops hook1, hook2;

unsigned int increaseTTL(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    iph->ttl = 80;
    return NF_ACCEPT;
}

static int __init registerFilter(void) {
    printk(KERN_INFO "Registering filters.\n");

    hook1.hook = increaseTTL;
    hook1.hooknum = NF_INET_LOCAL_IN;
    hook1.pf = PF_INET;
    hook1.priority = -100;
    nf_register_net_hook(&init_net, &hook1);

    return 0;
}

static void __exit removeFilter(void) {
    printk(KERN_INFO "The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook1);
}

module_init(registerFilter);
module_exit(removeFilter);
