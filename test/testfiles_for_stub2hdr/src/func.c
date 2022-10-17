typedef int ext_t;
static void int_f1(ext_t p) {}

void f1() {}
void f2(void) {}
void f3(int p) {}
void f4(int p, ...) {}


// function attributes are parsed but not preserved in DWARF
int  __attribute__((deprecated)) old_fn() {}

// WIP
// void __attribute__((noreturn))   f5() {}
