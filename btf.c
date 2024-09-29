#include <byteswap.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <linux/kernel.h>
#include <linux/btf.h>
#include <gelf.h>

#include "btf.h"

static void btf_bswap_hdr(struct btf_header *h) {
	h->magic = bswap_16(h->magic);
	h->hdr_len = bswap_32(h->hdr_len);
	h->type_off = bswap_32(h->type_off);
	h->type_len = bswap_32(h->type_len);
	h->str_off = bswap_32(h->str_off);
	h->str_len = bswap_32(h->str_len);
}


static int btf_parse_hdr(struct btf *btf) {
	struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			return -ENOTSUP;
		}
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		return -EINVAL;
	}

	return 0;
}


static int btf_parse_type_sec(struct btf *btf) {
	struct btf_header *hdr = btf->hdr;
	void *next_type = btf->types_data;
	void *end_type = next_type + hdr->type_len;
	int err, type_size;

	while (next_type + sizeof(struct btf_type) <= end_type) {
		if (btf->swapped_endian)
			btf_bswap_type_base(next_type);

		type_size = btf_type_size(next_type);
		if (type_size < 0)
			return type_size;
		if (next_type + type_size > end_type) {
			return -EINVAL;
		}

		if (btf->swapped_endian && btf_bswap_type_rest(next_type))
			return -EINVAL;

		err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
		if (err)
			return err;

		next_type += type_size;
		btf->nr_types++;
	}

	if (next_type != end_type) {
		return -EINVAL;
	}

	return 0;
}


static struct btf* btf_new(const void* data, __u32 size, struct btf* base_btf) {
    struct btf* btf;
    int err;

    btf = calloc(1, sizeof(struct btf));
    btf->nr_types = 0;
    btf->start_id = 1;
    btf->start_str_off = 0;
    btf->fd = -1;

    btf->raw_data = malloc(size);
    if (!btf->raw_data) {
        err = -ENOMEM;
        goto done;
    }

    memcpy(btf->raw_data, data, size);
    btf->raw_size = size;

    btf->hdr = btf->raw_data;
    err = btf_parse_hdr(btf);
    err = err ? : btf_parse_type_sec(btf);




    return btf;
done:
    return NULL;
}

static struct btf* btf_parse_raw(const char* path) {
    struct btf* btf = NULL;
    void* data = NULL;
    FILE* file = NULL;
    __u16 magic;
    int err = 0;
    long sz;

    file = fopen(path, "rbe");
    if (!file) {
        err = -errno;
        goto err_out;
    }

    if (fread(&magic, 1, sizeof(magic), file) < sizeof(magic)) {
        err = -EIO;
        goto err_out;
    }

    if (magic != BTF_MAGIC) {
        err = -EPROTO;
        goto err_out;
    }

    if (fseek(file, 0, SEEK_END)) {
        err = -errno;
        goto err_out;
    }

    sz = ftell(file);
    if (sz < 0) {
        err = -errno;
        goto err_out;
    }
    //goto statrt
    if (fseek(file, 0, SEEK_SET)) {
        err = -errno;
        goto err_out;
    }

    data = malloc(sz);
    if (!data) {
        err = -ENOMEM;
        goto err_out;
    }

    if (fread(data, 1, sz, file) < sz) {
        err = -EIO;
        goto err_out;
    }

    btf = btf_new(data, sz, NULL);

    return btf;

err_out:
    free(data);
    if (file) {
        fclose(file);
    }
    return btf;//todo
}


struct btf* btf_parse(const char* path) {
    struct btf* btf;
    int err;

    btf = btf_parse_raw(path);

    return btf;
}


struct btf* btf_load_vmlinux(const char* path) {
    //char path[PATH_MAX + 1];
	struct utsname buf;
	//struct btf *btf;
	int i, err;
    
    const char *sysfs_btf_path = "/sys/kernel/btf/vmlinux";

    if (faccessat(AT_FDCWD, sysfs_btf_path, F_OK, AT_EACCESS) < 0) {
		printf("kernel BTF is missing at '%s', was CONFIG_DEBUG_INFO_BTF enabled?\n",
			sysfs_btf_path);
	}

    btf_parse(sysfs_btf_path);
}