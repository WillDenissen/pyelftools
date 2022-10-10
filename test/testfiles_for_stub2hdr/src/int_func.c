struct int_t {
    int x;
};

struct ext_t {
    double x;
};

// internal
static void* h_int(struct int_t p) {}

//external
void* h_ext(struct ext_t p) {}
