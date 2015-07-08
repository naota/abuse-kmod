#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include "abuse.h"

int main()
{
  int err;

  int fd = open("/dev/abctl", O_RDONLY);
  assert(fd >= 0);

  // cannot add existing device
  int r = ioctl(fd, ABUSE_CTL_ADD, 0); err = errno;
  perror("add existing");
  assert(r < 0);
  assert(err == EEXIST);

  const int NEWDEV = 10;
  struct stat s;
  char devname[32];
  sprintf(devname, "/dev/abuse%d", NEWDEV);

  r = stat(devname, &s); err = errno;
  perror("missing device check");
  assert(r == -1);
  assert(err == ENOENT);

  // add missing device
  r = ioctl(fd, ABUSE_CTL_ADD, NEWDEV); err = errno;
  perror("add missing");
  assert(r == NEWDEV);

  r = stat(devname, &s); err = errno;
  perror("added device check");
  assert(r == 0);

  // remove alloced device
  r = ioctl(fd, ABUSE_CTL_REMOVE, NEWDEV); err = errno;
  perror("remove device");
  assert(r == NEWDEV);

  r = stat(devname, &s); err = errno;
  perror("removed device check");
  assert(r == -1);
  assert(err == ENOENT);

  // remove missing device
  r = ioctl(fd, ABUSE_CTL_REMOVE, NEWDEV); err = errno;
  perror("remove missing device");
  assert(r == -1);
  assert(err == ENOENT);

  close(fd);

  printf("All test PASS!\n");

  return 0;
}
