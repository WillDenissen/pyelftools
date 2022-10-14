struct s1_t {
    double x;
    double y;
};
struct s1_t s1;

struct s2_t {
    double x, y;
};
struct s2_t s2_t;

struct s3_t {
    struct s4_t {
        double x;
        double y;
    };
    double z;
};
struct s3_t s3;

// WIP
// struct s5_t {
//     struct {
//         double x;
//         double y;
//     };
//     double z;
// };
// struct s5_t s5;
