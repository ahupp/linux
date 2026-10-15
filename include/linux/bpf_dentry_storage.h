/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_DENTRY_STORAGE_H
#define _BPF_DENTRY_STORAGE_H

struct dentry;
#ifdef CONFIG_BPF_SYSCALL
void bpf_dentry_storage_free(struct dentry *dentry);
#else
static inline void bpf_dentry_storage_free(struct dentry *dentry) {}
#endif

#endif
