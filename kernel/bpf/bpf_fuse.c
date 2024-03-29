// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Google LLC

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/bpf_fuse.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>

void *bpf_fuse_get_writeable(struct fuse_buffer *arg, u64 size, bool copy)
{
	void *writeable_val;

	if (arg->flags & BPF_FUSE_IMMUTABLE)
		return 0;

	if (size <= arg->size &&
			(!(arg->flags & BPF_FUSE_MUST_ALLOCATE) ||
			  (arg->flags & BPF_FUSE_ALLOCATED))) {
		if (arg->flags & BPF_FUSE_VARIABLE_SIZE)
			arg->size = size;
		arg->flags |= BPF_FUSE_MODIFIED;
		return arg->data;
	}
	/* Variable sized arrays must stay below max size. If the buffer must be fixed size,
	 * don't change the allocated size. Verifier will enforce requested size for accesses
	 */
	if (arg->flags & BPF_FUSE_VARIABLE_SIZE) {
		if (size > arg->max_size)
			return 0;
	} else {
		if (size > arg->size)
			return 0;
		size = arg->size;
	}

	if (size != arg->size && size > arg->max_size)
		return 0;

	/* If our buffer is big enough, just adjust size */
	if (size <= arg->alloc_size) {
		if (!copy)
			arg->size = size;
		arg->flags |= BPF_FUSE_MODIFIED;
		return arg->data;
	}

	writeable_val = kzalloc(size, GFP_KERNEL);
	if (!writeable_val)
		return 0;

	arg->alloc_size = size;
	/* If we're copying the buffer, assume the same amount is used. If that isn't the case,
	 * caller must change size. Otherwise, assume entirety of new buffer is used.
	 */
	if (copy)
		memcpy(writeable_val, arg->data, (arg->size > size) ? size : arg->size);
	else
		arg->size = size;

	if (arg->flags & BPF_FUSE_ALLOCATED)
		kfree(arg->data);
	arg->data = writeable_val;

	arg->flags |= BPF_FUSE_ALLOCATED | BPF_FUSE_MODIFIED;

	return arg->data;
}
EXPORT_SYMBOL(bpf_fuse_get_writeable);

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_fuse_get_rw_dynptr(struct fuse_buffer *buffer, struct bpf_dynptr_kern *dynptr__uninit, u64 size, bool copy)
{
	buffer->data = bpf_fuse_get_writeable(buffer, size, copy);
	bpf_dynptr_init(dynptr__uninit, buffer->data, BPF_DYNPTR_TYPE_LOCAL, 0, buffer->size);
}

__bpf_kfunc void bpf_fuse_get_ro_dynptr(const struct fuse_buffer *buffer, struct bpf_dynptr_kern *dynptr__uninit)
{
	bpf_dynptr_init(dynptr__uninit, buffer->data, BPF_DYNPTR_TYPE_LOCAL, 0, buffer->size);
	bpf_dynptr_set_rdonly(dynptr__uninit);
}

__bpf_kfunc uint32_t bpf_fuse_return_len(struct fuse_buffer *buffer)
{
	return buffer->size;
}
__diag_pop();
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(fuse_kfunc_set)
BTF_ID_FLAGS(func, bpf_fuse_get_rw_dynptr)
BTF_ID_FLAGS(func, bpf_fuse_get_ro_dynptr)
BTF_ID_FLAGS(func, bpf_fuse_return_len)
BTF_KFUNCS_END(fuse_kfunc_set)

static const struct btf_kfunc_id_set bpf_fuse_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &fuse_kfunc_set,
};

static const struct bpf_func_proto *bpf_fuse_get_func_proto(enum bpf_func_id func_id,
							      const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_fuse_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

const struct btf_type *fuse_buffer_struct_type;

static int bpf_fuse_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == fuse_buffer_struct_type) {
		bpf_log(log,
			"direct access to fuse_buffer is disallowed\n");
		return -EACCES;
	}

	return 0;
}

static const struct bpf_verifier_ops bpf_fuse_verifier_ops = {
	.get_func_proto		= bpf_fuse_get_func_proto,
	.is_valid_access	= bpf_fuse_is_valid_access,
	.btf_struct_access	= bpf_fuse_btf_struct_access,
};

static int bpf_fuse_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	//if (is_unsupported(__btf_member_bit_offset(t, member) / 8))
	//	return -ENOTSUPP;
	return 0;
}

static int bpf_fuse_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	const struct fuse_ops *uf_ops;
	struct fuse_ops *f_ops;
	u32 moff;

	uf_ops = (const struct fuse_ops *)udata;
	f_ops = (struct fuse_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct fuse_ops, name):
		if (bpf_obj_name_cpy(f_ops->name, uf_ops->name,
				     sizeof(f_ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_fuse_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "fuse_buffer", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	fuse_buffer_struct_type = btf_type_by_id(btf, type_id);

	return 0;
}

static struct bpf_fuse_ops_attach *fuse_reg = NULL;

static int bpf_fuse_reg(void *kdata)
{
	if (fuse_reg)
		return fuse_reg->fuse_register_bpf(kdata);
	pr_warn("Cannot register fuse_ops, FUSE not found");
	return -EOPNOTSUPP;
}

static void bpf_fuse_unreg(void *kdata)
{
	if(fuse_reg)
		return fuse_reg->fuse_unregister_bpf(kdata);
}

int register_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops)
{
	fuse_reg = reg_ops;
	return 0;
}
EXPORT_SYMBOL_GPL(register_fuse_bpf);

void unregister_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops)
{
	if (reg_ops == fuse_reg)
		fuse_reg = NULL;
	else
		pr_warn("Refusing to unregister unregistered FUSE");
}
EXPORT_SYMBOL_GPL(unregister_fuse_bpf);

/* CFI Stubs */
static uint32_t bpf_fuse_default_filter(const struct bpf_fuse_meta_info *meta)
{
	return 0;
}

static uint32_t bpf_fuse_open_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_open_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_opendir_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_opendir_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_create_open_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_create_in *in, struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_create_open_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_create_in *in, const struct fuse_buffer *name,
				struct fuse_entry_out *entry_out, struct fuse_open_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_release_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_release_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_releasedir_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_releasedir_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_flush_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_flush_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_flush_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_flush_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_lseek_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_lseek_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_lseek_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_lseek_in *in,
				struct fuse_lseek_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_copy_file_range_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_copy_file_range_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_copy_file_range_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_copy_file_range_in *in,
				struct fuse_write_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_fsync_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_fsync_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_dir_fsync_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_dir_fsync_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_getxattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in, struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_getxattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in, const struct fuse_buffer *name,
				struct fuse_buffer *value, struct fuse_getxattr_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_listxattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_listxattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in,
				struct fuse_buffer *value, struct fuse_getxattr_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_setxattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_setxattr_in *in, struct fuse_buffer *name,
					struct fuse_buffer *value)
{
	return 0;
}

static uint32_t bpf_fuse_setxattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_setxattr_in *in, const struct fuse_buffer *name,
					const struct fuse_buffer *value)
{
	return 0;
}

static uint32_t bpf_fuse_removexattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_removexattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_read_iter_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_read_iter_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_iter_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_write_iter_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_write_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_write_iter_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_write_in *in,
				struct fuse_write_iter_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_file_fallocate_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_fallocate_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_file_fallocate_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fallocate_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_lookup_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_lookup_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	return 0;
}

static uint32_t bpf_fuse_mknod_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_mknod_in *in, struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_mknod_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_mknod_in *in, const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_mkdir_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_mkdir_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_mkdir_in *in, const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_rmdir_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_rmdir_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_rename2_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_rename2_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	return 0;
}

static uint32_t bpf_fuse_rename2_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename2_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name)
{
	return 0;
}

static uint32_t bpf_fuse_rename_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_rename_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	return 0;
}

static uint32_t bpf_fuse_rename_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name)
{
	return 0;
}

static uint32_t bpf_fuse_unlink_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_unlink_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_link_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_link_in *in, struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_link_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_link_in *in, const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_getattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_getattr_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_getattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getattr_in *in,
				struct fuse_attr_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_setattr_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_setattr_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_setattr_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_setattr_in *in,
				struct fuse_attr_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_statfs_prefilter(const struct bpf_fuse_meta_info *meta)
{
	return 0;
}

static uint32_t bpf_fuse_statfs_postfilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_statfs_out *out)
{
	return 0;
}

static uint32_t bpf_fuse_get_link_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_get_link_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	return 0;
}

static uint32_t bpf_fuse_symlink_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name, struct fuse_buffer *path)
{
	return 0;
}

static uint32_t bpf_fuse_symlink_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name, const struct fuse_buffer *path)
{
	return 0;
}

static uint32_t bpf_fuse_readdir_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_readdir_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_out *out, struct fuse_buffer *buffer)
{
	return 0;
}

static uint32_t bpf_fuse_access_prefilter(const struct bpf_fuse_meta_info *meta,
				struct fuse_access_in *in)
{
	return 0;
}

static uint32_t bpf_fuse_access_postfilter(const struct bpf_fuse_meta_info *meta,
				const struct fuse_access_in *in)
{
	return 0;
}

static struct fuse_ops __bpf_fuse_ops = {
	.default_filter = bpf_fuse_default_filter,
	.open_prefilter = bpf_fuse_open_prefilter,
	.open_postfilter = bpf_fuse_open_postfilter,
	.opendir_prefilter = bpf_fuse_opendir_prefilter,
	.opendir_postfilter = bpf_fuse_opendir_postfilter,
	.create_open_prefilter = bpf_fuse_create_open_prefilter,
	.create_open_postfilter = bpf_fuse_create_open_postfilter,
	.release_prefilter = bpf_fuse_release_prefilter,
	.release_postfilter = bpf_fuse_release_postfilter,
	.releasedir_prefilter = bpf_fuse_releasedir_prefilter,
	.releasedir_postfilter = bpf_fuse_releasedir_postfilter,
	.flush_prefilter = bpf_fuse_flush_prefilter,
	.flush_postfilter = bpf_fuse_flush_postfilter,
	.lseek_prefilter = bpf_fuse_lseek_prefilter,
	.lseek_postfilter = bpf_fuse_lseek_postfilter,
	.copy_file_range_prefilter = bpf_fuse_copy_file_range_prefilter,
	.copy_file_range_postfilter = bpf_fuse_copy_file_range_postfilter,
	.fsync_prefilter = bpf_fuse_fsync_prefilter,
	.fsync_postfilter = bpf_fuse_fsync_postfilter,
	.dir_fsync_prefilter = bpf_fuse_dir_fsync_prefilter,
	.dir_fsync_postfilter = bpf_fuse_dir_fsync_postfilter,
	.getxattr_prefilter = bpf_fuse_getxattr_prefilter,
	.getxattr_postfilter = bpf_fuse_getxattr_postfilter,
	.listxattr_prefilter = bpf_fuse_listxattr_prefilter,
	.listxattr_postfilter = bpf_fuse_listxattr_postfilter,
	.setxattr_prefilter = bpf_fuse_setxattr_prefilter,
	.setxattr_postfilter = bpf_fuse_setxattr_postfilter,
	.removexattr_prefilter = bpf_fuse_removexattr_prefilter,
	.removexattr_postfilter = bpf_fuse_removexattr_postfilter,
	.read_iter_prefilter = bpf_fuse_read_iter_prefilter,
	.read_iter_postfilter = bpf_fuse_read_iter_postfilter,
	.write_iter_prefilter = bpf_fuse_write_iter_prefilter,
	.write_iter_postfilter = bpf_fuse_write_iter_postfilter,
	.file_fallocate_prefilter = bpf_fuse_file_fallocate_prefilter,
	.file_fallocate_postfilter = bpf_fuse_file_fallocate_postfilter,
	.lookup_prefilter = bpf_fuse_lookup_prefilter,
	.lookup_postfilter = bpf_fuse_lookup_postfilter,
	.mknod_prefilter = bpf_fuse_mknod_prefilter,
	.mknod_postfilter = bpf_fuse_mknod_postfilter,
	.mkdir_prefilter = bpf_fuse_mkdir_prefilter,
	.mkdir_postfilter = bpf_fuse_mkdir_postfilter,
	.rmdir_prefilter = bpf_fuse_rmdir_prefilter,
	.rmdir_postfilter = bpf_fuse_rmdir_postfilter,
	.rename2_prefilter = bpf_fuse_rename2_prefilter,
	.rename2_postfilter = bpf_fuse_rename2_postfilter,
	.rename_prefilter = bpf_fuse_rename_prefilter,
	.rename_postfilter = bpf_fuse_rename_postfilter,
	.unlink_prefilter = bpf_fuse_unlink_prefilter,
	.unlink_postfilter = bpf_fuse_unlink_postfilter,
	.link_prefilter = bpf_fuse_link_prefilter,
	.link_postfilter = bpf_fuse_link_postfilter,
	.getattr_prefilter = bpf_fuse_getattr_prefilter,
	.getattr_postfilter = bpf_fuse_getattr_postfilter,
	.setattr_prefilter = bpf_fuse_setattr_prefilter,
	.setattr_postfilter = bpf_fuse_setattr_postfilter,
	.statfs_prefilter = bpf_fuse_statfs_prefilter,
	.statfs_postfilter = bpf_fuse_statfs_postfilter,
	.get_link_prefilter = bpf_fuse_get_link_prefilter,
	.get_link_postfilter = bpf_fuse_get_link_postfilter,
	.symlink_prefilter = bpf_fuse_symlink_prefilter,
	.symlink_postfilter = bpf_fuse_symlink_postfilter,
	.readdir_prefilter = bpf_fuse_readdir_prefilter,
	.readdir_postfilter = bpf_fuse_readdir_postfilter,
	.access_prefilter = bpf_fuse_access_prefilter,
	.access_postfilter = bpf_fuse_access_postfilter,
};

static struct bpf_struct_ops bpf_fuse_ops = {
	.verifier_ops = &bpf_fuse_verifier_ops,
	.reg = bpf_fuse_reg,
	.unreg = bpf_fuse_unreg,
	.check_member = bpf_fuse_check_member,
	.init_member = bpf_fuse_init_member,
	.init = bpf_fuse_init,
	.name = "fuse_ops",
	.cfi_stubs = &__bpf_fuse_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_fuse_ops_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &bpf_fuse_kfunc_set);
	ret = ret ?: register_bpf_struct_ops(&bpf_fuse_ops, fuse_ops);

	return ret;
}
late_initcall(bpf_fuse_ops_init);
