// common
int v1[2];
int *v2[1][2];
int * const (** const (***(v3[1])[2])[3]);
int ***v4[1][2][3];

int g(
  int **var
) {}
int f(
  int *var[3]  // var[3] is interpreted as *var
) {}
 
