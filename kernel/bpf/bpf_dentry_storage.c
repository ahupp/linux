// SPDX-License-Identifier: GPL-2.0
/* Dentry-local BPF storage. Based on bpf_inode_storage.c. */
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/bpf_dentry_storage.h>
#include <linux/btf_ids.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/rcupdate_trace.h>

DEFINE_BPF_STORAGE_CACHE(dentry_storage_cache);

static struct bpf_local_storage __rcu **dentry_storage_ptr(void *owner)
{
	struct dentry *dentry = owner;

	return &dentry->d_bpf_storage;
}

static struct bpf_local_storage_data *
dentry_storage_lookup(struct dentry *dentry, struct bpf_map *map, bool cache)
{
	struct bpf_local_storage *storage;

	storage = rcu_dereference_check(dentry->d_bpf_storage,
					bpf_rcu_lock_held());
	if (!storage)
		return NULL;
	return bpf_local_storage_lookup(storage,
			(struct bpf_local_storage_map *)map, cache);
}

void bpf_dentry_storage_free(struct dentry *dentry)
{
	struct bpf_local_storage *storage;

	rcu_read_lock();
	storage = rcu_dereference(dentry->d_bpf_storage);
	if (storage)
		bpf_local_storage_destroy(storage);
	rcu_read_unlock();
}

static void *bpf_fd_dentry_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct fd f = fdget_raw(*(int *)key);

	if (!f.file)
		return ERR_PTR(-EBADF);
	sdata = dentry_storage_lookup(f.file->f_path.dentry, map, true);
	fdput(f);
	return sdata ? sdata->data : NULL;
}

static long bpf_fd_dentry_storage_update_elem(struct bpf_map *map, void *key,
					    void *value, u64 flags)
{
	struct bpf_local_storage_data *sdata;
	struct fd f = fdget_raw(*(int *)key);

	if (!f.file)
		return -EBADF;
	sdata = bpf_local_storage_update(f.file->f_path.dentry,
			(struct bpf_local_storage_map *)map, value,
			flags, GFP_ATOMIC);
	fdput(f);
	return PTR_ERR_OR_ZERO(sdata);
}

static int dentry_storage_delete(struct dentry *dentry, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = dentry_storage_lookup(dentry, map, false);
	if (!sdata)
		return -ENOENT;
	bpf_selem_unlink(SELEM(sdata), false);
	return 0;
}

static long bpf_fd_dentry_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct fd f = fdget_raw(*(int *)key);
	int error;

	if (!f.file)
		return -EBADF;
	error = dentry_storage_delete(f.file->f_path.dentry, map);
	fdput(f);
	return error;
}

/* gfp_flags is supplied by the verifier, not the BPF caller. */
BPF_CALL_5(bpf_dentry_storage_get, struct bpf_map *, map,
	   struct dentry *, dentry, void *, value, u64, flags,
	   gfp_t, gfp_flags)
{
	struct bpf_local_storage_data *sdata;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!dentry || flags & ~BPF_LOCAL_STORAGE_GET_F_CREATE)
		return (unsigned long)NULL;
	sdata = dentry_storage_lookup(dentry, map, true);
	if (sdata)
		return (unsigned long)sdata->data;
	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;
	/* The callback must hold a reference to dentry when creating storage. */
	sdata = bpf_local_storage_update(dentry,
			(struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST, gfp_flags);
	if (IS_ERR(sdata))
		/* Another invocation may have created this owner's storage. */
		sdata = dentry_storage_lookup(dentry, map, true);
	return sdata ? (unsigned long)sdata->data : (unsigned long)NULL;
}

BPF_CALL_2(bpf_dentry_storage_delete, struct bpf_map *, map,
	   struct dentry *, dentry)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	return dentry ? dentry_storage_delete(dentry, map) : -EINVAL;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *dentry_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &dentry_storage_cache, false);
}

static void dentry_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &dentry_storage_cache, NULL);
}

const struct bpf_map_ops dentry_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = dentry_storage_map_alloc,
	.map_free = dentry_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_fd_dentry_storage_lookup_elem,
	.map_update_elem = bpf_fd_dentry_storage_update_elem,
	.map_delete_elem = bpf_fd_dentry_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr = dentry_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_dentry_storage_btf_ids, struct, dentry)

const struct bpf_func_proto bpf_dentry_storage_get_proto = {
	.func = bpf_dentry_storage_get,
	.ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id = &bpf_dentry_storage_btf_ids[0],
	.arg3_type = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_dentry_storage_delete_proto = {
	.func = bpf_dentry_storage_delete,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id = &bpf_dentry_storage_btf_ids[0],
};
