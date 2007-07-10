#include <ei.h>

#define DECODE_STRING(str) decode_string(buf, &index, str)

typedef char byte;

int decode_string(char *buf, int *index, char **str);

byte *read_cmd(byte *buf, int *size);
int write_cmd(ei_x_buff* x);
int read_exact(byte *buf, int len);
int write_exact(byte *buf, int len);
