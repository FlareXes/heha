#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops hook1, hook2;

unsigned int hello1(void *priv, struct sk_buff *skb,
                    const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;

    if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = udp_hdr(skb);
        if (ntohs(udp_header->dest) == 53) {
            printk(KERN_INFO "*** Blocking UDP traffic on port 53\n");
            return NF_DROP;
        }
    } else if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (ntohs(tcp_header->dest) == 53) {
            printk(KERN_INFO "*** Blocking TCP traffic on port 53\n");
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

unsigned int hello2(void *priv, struct sk_buff *skb,
                    const struct nf_hook_state *state) {
    return NF_ACCEPT; // This hook will not be used for blocking port 53
}

static int __init registerFilter(void) {
    printk(KERN_INFO "Registering filters.\n");

    hook1.hook = hello1;
    hook1.hooknum = NF_INET_LOCAL_OUT;
    hook1.pf = PF_INET;
    hook1.priority = -100;
    nf_register_net_hook(&init_net, &hook1);

    // hook2 will not be used for blocking port 53, so it's not modified

    return 0;
}

static void __exit removeFilter(void) {
    printk(KERN_INFO "The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook1);
}

module_init(registerFilter);
module_exit(removeFilter);
