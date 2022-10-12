// This is not a stub as: 
// 1) global variables are initialized
// 2) global functions have implementations 

// test to check whether we can detect these stub requirement violations

struct vect_t {
    int x,y;
};

struct vect_t bad_var = {.x = 3, .y = 4};

int bad_func(int x) {
  return x + 3;
}
