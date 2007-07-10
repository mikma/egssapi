#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "port_util.h"

int decode_string(char *buf, int *index, char **str)
{
    int type;
    int len;

    *str = NULL;

    if (ei_get_type(buf, index, &type, &len)) return 5;

    *str = malloc(len);

    if (ei_decode_string(buf, index, *str)) return 8;

    return 0;
}

/*-----------------------------------------------------------------
 * Data marshalling functions
 *----------------------------------------------------------------*/
byte *read_cmd(byte *buf, int *size)
{
    int len;

    if (read_exact(buf, 2) != 2)
	return NULL;
    len = ((unsigned char)buf[0] << 8) | (unsigned char)buf[1];

    if (len > *size) {
	buf = realloc(buf, len);
	if (buf == NULL)
	    return NULL;
	*size = len;
    }
    
    if (read_exact(buf, len) < 0)
	return NULL;

    return buf;
}

int write_cmd(ei_x_buff *buff)
{
    byte li;

    li = (buff->index >> 8) & 0xff; 
    write_exact(&li, 1);
    li = buff->index & 0xff;
    write_exact(&li, 1);

    return write_exact(buff->buff, buff->index);
}

int read_exact(byte *buf, int len)
{
    int i, got=0;

    do {
	if ((i = read(0, buf+got, len-got)) <= 0) {
/* 	    perror("read"); */
/* 	    fprintf(stderr, "read_exact failed %d %d %p\n", i, got, buf+got); */
	    return i;
	}
	got += i;
    } while (got<len);

/*     fprintf(stderr, "read_exact: %d\n", len); */
    return len;
}

int write_exact(byte *buf, int len)
{
    int i, wrote = 0;

    do {
	if ((i = write(1, buf+wrote, len-wrote)) <= 0)
	    return i;
	wrote += i;
    } while (wrote<len);

    return len;
}
