.. SPDX-License-Identifier: GPL-2.0-only

==========================
BPF_MAP_TYPE_DENTRY_STORAGE
==========================

This experimental map type associates a BPF-defined value with a live
``struct dentry``. Each map defines an independent storage namespace. Values
are freed when either the map or the owning dentry is destroyed. They do not
pin dentries and are not persistent filesystem metadata.

Creation
========

Use a BTF-described ``int`` key, a BTF-described value, ``max_entries = 0``,
and ``BPF_F_NO_PREALLOC``. The kernel allocates entries on demand. Map creation
requires the same privileges as inode-local storage. This implementation is
built with ``CONFIG_BPF_SYSCALL``; it does not use ``d_fsdata`` or require a
filesystem-specific extension to that field.

Kernel BPF API
==============

.. code-block:: c

    void *bpf_dentry_storage_get(struct bpf_map *map, struct dentry *dentry,
                                void *initial_value, __u64 flags);
    long bpf_dentry_storage_delete(struct bpf_map *map, struct dentry *dentry);

The get helper returns the map value or NULL. With
``BPF_LOCAL_STORAGE_GET_F_CREATE`` it creates missing storage, copying
``initial_value`` or initializing to zero when that argument is NULL. No
other flags are accepted. Delete returns zero, ``-ENOENT`` for absent
storage, or ``-EINVAL`` for a NULL owner.

These helpers are exposed to BPF LSM and this branch's FUSE struct_ops
programs. The callback must keep the owner alive and hold BPF's required RCU
read protection. A returned value pointer must not escape that invocation.
The verifier checks the owner BTF type and requires the matching map type.
The verifier supplies the allocation context as a hidden helper argument.

Userspace API
=============

``BPF_MAP_LOOKUP_ELEM``, ``BPF_MAP_UPDATE_ELEM``, and
``BPF_MAP_DELETE_ELEM`` use an open file descriptor as their ``int`` key.
The owner is that file's ``f_path.dentry``. ``O_PATH`` descriptors are
accepted. Update supports the ordinary ``BPF_ANY``, ``BPF_NOEXIST``, and
``BPF_EXIST`` semantics. Invalid descriptors return ``-EBADF``.
``BPF_MAP_GET_NEXT_KEY`` is unsupported. Negative dentries are accessible
from kernel callbacks but cannot be addressed through an ordinary file FD.

Identity and synchronization
============================

Two FDs for the same dentry share a value; two hard-link dentries can have
different values despite referring to one inode. Rename does not by itself
clear storage from a surviving dentry. Storage also survives unlink while
an FD retains that particular dentry. A negative dentry becoming positive
does not implicitly reset its value. Callers must track lookup generations
or explicitly invalidate metadata when their meaning changes.

Reclaim and later lookup may allocate a different dentry, with fresh storage,
for the same path. Dentry-local values therefore cannot be the sole source
of durable file IDs or dependency history. Use inode-local storage for
live-inode state and a filesystem identity/version index for longer-lived
records. Attach operation provenance to the task/request rather than
storing one current execution ID on a shared dentry.

Concurrent programs may access one value on different CPUs. Use supported
atomics or BPF spin locks where required. The implementation reuses BPF
local-storage RCU lifetime and map teardown machinery, with explicit dentry
allocation initialization and destruction hooks.
