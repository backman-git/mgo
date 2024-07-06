// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe//home/vagrant/workspace/mgo/tracee:main.target")
int BPF_KPROBE(target)
{
    bpf_printk("traget hit");
    return 0;
}