#ifndef BTF_H
#define BTF_H

struct btf *btf__load_vmlinux_btf(void);

__s32 btf_find_by_name_kind(const struct btf *btf, int start_id,
				   const char *type_name, __u32 kind);
#endif