// common
int v1[2];
int *v2[1][2];
int (*v3[1])[2];
int * const (** const (***v4[1])[2])[3];
int ***v5[1][2][3];

int g(
  int **var
) {}
int f(
  int *var[3]  // var[3] is interpreted as *var
) {}
 
