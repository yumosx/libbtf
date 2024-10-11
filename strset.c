struct strset{
    void* strs_data;
    size_t strs_data_len;
    size_t strs_data_cap;
    size_t strs_data_max_len;
};

static size_t strset_hash_fn(long key, void* ctx) {
    const struct strset* s = ctx;
    const char* str = s->strs_data + key;
    return str_hash(str);
}