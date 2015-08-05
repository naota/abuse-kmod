#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <unistd.h>
#include <string.h>
#include <sys/signalfd.h>
#include <openssl/sha.h>
#define __USE_GNU
#include <poll.h>
#include "abuse.h"

int fd;

void teardown()
{
  ioctl(fd, ABUSE_RESET);
  ioctl(fd, ABUSE_RELEASE);
  return;
}

const int max_queue = 1 << 16;
const long size = 1024 * 1024 * 1024;

int main(int argc, char *argv[])
{
  const char *abctlpath = "/dev/abctl";
  char *abdevpath = argv[1];

  unsigned char *data = malloc(size);
  if (data == NULL) {
    perror("malloc");
    return -1;
  }
  memset(data, 0, size);

  fd = open(abctlpath, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s: ", abctlpath);
    perror(NULL);
    return -1;
  }

  int devfd = open(abdevpath, O_RDWR);
  if (devfd < 0) {
    fprintf(stderr, "Failed to open %s: ", abdevpath);
    perror(NULL);
    return -1;
  }

  if (ioctl(fd, ABUSE_ACQUIRE, devfd) == -1)  {
    perror("ACQUIRE failed");
    return -1;
  }

  // check if disk is already there
  struct abuse_info info;
  if (ioctl(fd, ABUSE_GET_STATUS, &info) == -1) {
    perror("GET_STATUS failed");
    return -1;
  }
  if (info.ab_size > 0)
    ioctl(fd, ABUSE_RESET);

  // Generate disk
  info.ab_size = size;
  info.ab_blocksize = 4096;
  info.ab_max_queue = max_queue;
  if (ioctl(fd, ABUSE_SET_STATUS, &info) == -1) {
    perror("SET_STATUS failed");
    return -1;
  }

  const int FDCNT = 2;
  struct pollfd fds[FDCNT];
  sigset_t sigmask;

  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGINT);
  sigaddset(&sigmask, SIGTERM);
  sigaddset(&sigmask, SIGQUIT);

  fds[0].fd = fd;
  fds[0].events = POLLMSG;
  fds[1].fd = signalfd(-1, &sigmask, 0);
  fds[1].events = POLLIN;

  if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
    perror("sigprocmask failed");
    teardown();
    return -1;
  }

  printf("Ready\n"); fflush(stdout);
  // main loop waiting for IO
  // int max = 0;
  while (ppoll(fds, FDCNT, NULL, NULL) > 0) {
    if (fds[0].revents) {
      struct abuse_xfr_hdr xfr;
      struct abuse_vec vecs[max_queue];

      for(;;) {
	__u32 i;
	memset(&xfr, 0, sizeof(xfr));
	xfr.ab_transfer_address = (__u64) vecs;
	// read header
	if (ioctl(fd, ABUSE_GET_REQ, &xfr) == -1) {
	  if (errno != ENOMSG) {
	    perror("GET_BIO failed");
	    goto out;
	  }
	}
	if (xfr.ab_vec_count == 0)
	  break;

	/* printf("id = %p, " */
	/*        "command = %s (%d), " */
	/*        "sector = 0x%llx, " */
	/*        "result = 0x%x, " */
	/*        "vec_count = %d\n", */
	/*        (void*)xfr.ab_id, */
	/*        xfr.ab_command ? "WRITE": "READ", xfr.ab_command, */
	/*        xfr.ab_sector, */
	/*        xfr.ab_result, xfr.ab_vec_count); */

	// allocate receive/send buffer
	off_t pos = 0;
	for (i=0; i<xfr.ab_vec_count; ++i) {
	  vecs[i].ab_address = (__u64)(data + 512 * xfr.ab_sector + pos);
	  pos += vecs[i].ab_len;
	}
	if (ioctl(fd, ABUSE_PUT_REQ, &xfr) == -1) {
	  perror("PUT_BIO failed");
	  goto out;
	}
      }

      fds[0].revents = 0;
      fflush(stdout);
    }

    // got signal! closing
    if (fds[1].revents)
      break;
  }

 out:
  fprintf(stderr, "Exiting\n");
  teardown();
  close(devfd);
  close(fd);
  return 0;
}
