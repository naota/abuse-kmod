#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "abuse.h"

int main()
{
  int err;

  int fd = open("/dev/abctl", O_RDONLY);
  assert(fd >= 0);

  // cannot add existing device
  int r = ioctl(fd, ABUSE_CTL_ADD, 0); err = errno;
  perror(NULL);
  assert(r < 0);
  assert(err == EEXIST);

  // add unused device
  r = ioctl(fd, ABUSE_CTL_ADD, 10);
  perror(NULL);
  assert(r == 10);

  close(fd);
  return 0;
}
