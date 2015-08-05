#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "libabuse.h"

#define SIZE ((size_t)1024 * 1024 * 1024)

static void *mem_address(off_t offset, size_t len, int read, void *userdata)
{
  void *data = userdata;

  assert(offset+len <= SIZE);
  assert(read || !read);

  return data+offset;
}

static struct abuse_operations aops = {
  .address = mem_address,
  .read_complete = NULL,
  .write_complete = NULL,
  .size = SIZE,
};

int main(int argc, char *argv[])
{
  void *data = malloc(aops.size);
  if (data == NULL)
    return -1;
  printf("start main\n");
  return abuse_main(argv[1], &aops, data);
}
