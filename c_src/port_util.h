#include <ei.h>

typedef char byte;

byte *read_cmd(byte *buf, int *size);
int write_cmd(ei_x_buff* x);
int read_exact(byte *buf, int len);
int write_exact(byte *buf, int len);
