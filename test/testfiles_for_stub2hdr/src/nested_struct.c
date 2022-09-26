struct istruct_t {
    double iz;
};

struct astruct_t {
    int   i;
    float y;
    struct istruct_t z;
};

void afunc(struct astruct_t p) {}
