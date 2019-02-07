#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pinglat - estimate upper bound for local ICMP ECHO software processing latency
from bcc import BPF
from time import sleep

# name of interface we are tracing on
ifname="eth0"

prog = r"""
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/icmp.h>

// event represents 1 INTR->icmp_echo->icmp_reply event
struct event {
    u64 tint;           // t of interrupt on iface
    int nint;           // # of interrupt on iface before it got to icmp_echo
                        // ( potentially there can be several interrupts before we get to icmp_echo.
                        //   we take conservative approach and start counting time from the first )

    u64 techo;          // t when it got to icmp_echo
    //u64 techo_reply;  // t when icmp_echo finished (it calls icmp_reply inside)
                        //   we do not need to store it as this is the last point of the event
};

BPF_ARRAY(event, struct event, 1);  // current in-flight event

BPF_HISTOGRAM(dist_dt_int_echo);    // dt int - icmp_echo
BPF_HISTOGRAM(dist_dt_echo_tx);     // dt icmp_echo - tx
BPF_HISTOGRAM(dist_dt_int_tx);      // dt int - tx
BPF_HISTOGRAM(dist_nint);

// # out-of-sync events
// 1 - missed interrupt
// 2 - second icmp_echo without processing for first completed
// 3 - icmp_echo ret without interrupt
// 4 - icmp_echo ret without icmp_echo
BPF_HISTOGRAM(outofsync);

// remember t(last-interrupt) on interface
int kprobe__handle_irq_event_percpu(struct pt_regs *ctx, struct irq_desc *desc) {
    const char *irqname = desc->action->name;
"""

# irqname != ifname -> return
prog += "    char c;\n"
for i, c in enumerate(ifname):
    prog += "    bpf_probe_read(&c, 1, &irqname[%d]);   if (c != '%s') return 0;\n" % (i, c)

prog += r"""
    u64 ts = bpf_ktime_get_ns();
    int z=0; struct event zev = {};

    struct event *ev = event.lookup_or_init(&z, &zev);

    ev->tint = ts;  // t of _last_ interrupt
    ev->nint++;     // verifying it is sane (e.g. =2 means TXintr RXintr icmp_echo icmp_reply TXintr RXintr ...

    //bpf_trace_printk("interrupt: %s\n", irqname);
    return 0;
}


// remember t(icmp_echo) - when we received ICMP ECHO
int kprobe__icmp_echo(struct pt_regs *ctx, struct sk_buff *skb) {
    u64 ts = bpf_ktime_get_ns();
    int z=0; struct event zev = {};

    struct event *ev = event.lookup_or_init(&z, &zev);
    if (ev->tint == 0) {
        // missed interrupt
        outofsync.increment(1);
        return 0;
    }

    if (ev->techo != 0) {
        // second icmp_echo without previous processed
        outofsync.increment(2);
        return 0;
    }

    ev->techo = ts;

    //bpf_trace_printk("ping id: %d  seq: %d  dint: %dns\n", h.un.echo.id, h.un.echo.sequence, ts - tint);
    return 0;
}

// remember t(reply)
//TRACEPOINT_PROBE(net, net_dev_xmit) {
//    const char *devname = (void *)args + (args->data_loc_name & 0xffff);
int kretprobe__icmp_echo(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    int z=0; struct event zev = {};

    struct event *ev = event.lookup_or_init(&z, &zev);
    if (ev->tint == 0) {
       // icmp_echo ret without interrupt
       outofsync.increment(3);
       return 0;
    }

    if (ev->techo == 0) {
       // icmp_echo ret without icmp_echo
       outofsync.increment(4);
       return 0;
    }

    u64 dt_int_echo = ev->techo - ev->tint;
    u64 dt_int_tx   = ts - ev->tint;
    u64 dt_echo_tx  = ts - ev->techo;
    int nint        = ev->nint;

    *ev = zev;

    dist_dt_int_echo .increment(bpf_log2l(dt_int_echo   / (u64)(1E3)));
    dist_dt_echo_tx  .increment(bpf_log2l(dt_echo_tx    / (u64)(1E3)));
    dist_dt_int_tx   .increment(bpf_log2l(dt_int_tx     / (u64)(1E3)));
    dist_nint        .increment(nint);

    //bpf_trace_printk("net tx from under icmp_echo\n");
    return 0;
}
"""

prog = prog.replace("IFNAME", ifname)

#print prog

b = BPF(text=prog)
#b.trace_print()

while 1:
    sleep(3)
    print '-'*40
    b["outofsync"].print_linear_hist("outofsync")
    b["outofsync"].clear()

    b["dist_nint"].print_linear_hist("nint")
    b["dist_nint"].clear()

    b["dist_dt_int_echo"].print_log2_hist("int - icmp_echo (μs)")
    b["dist_dt_int_echo"].clear()

    b["dist_dt_echo_tx"].print_log2_hist("icmp_echo - tx (μs)")
    b["dist_dt_echo_tx"].clear()

    b["dist_dt_int_tx"].print_log2_hist("int - tx (μs)")
    b["dist_dt_int_tx"].clear()
