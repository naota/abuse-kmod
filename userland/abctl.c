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
  return;
}

const int max_queue = 256;

int main(int argc, char *argv[])
{
  char *abctlpath = argv[1];

  fd = open(abctlpath, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s: ", abctlpath);
    perror(NULL);
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
  info.ab_size = 16 * 4096;
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

  // main loop waiting for IO
  while (ppoll(fds, FDCNT, NULL, NULL) > 0) {
    if (fds[0].revents) {
      __u32 i;
      struct abuse_xfr_hdr xfr;
      struct abuse_vec *vecs = malloc(max_queue * sizeof(struct abuse_vec));

      memset(&xfr, 0, sizeof(xfr));
      xfr.ab_transfer_address = (__u64) vecs;
      // read header
      if (ioctl(fd, ABUSE_GET_REQ, &xfr) == -1) {
	free(vecs);
	perror("GET_BIO failed");
	teardown();
	return -1;
      }

      printf("id =\t\t%p\n"
	     "command =\t%s\n"
	     "sector = \t0x%llx\n"
	     "result =\t0x%x\n"
	     "vec_count =\t%d\n",
	     (void*)xfr.ab_id, xfr.ab_command ? "WRITE": "READ",
	     xfr.ab_sector,
	     xfr.ab_result, xfr.ab_vec_count);

      int write = xfr.ab_command;
      // allocate receive/send buffer
      for (i=0; i<xfr.ab_vec_count; ++i)
	vecs[i].ab_address = (__u64)malloc(vecs[i].ab_len);
      if (write) {
	ioctl(fd, ABUSE_PUT_REQ, &xfr);

	// Now we received data
	for (i=0; i<xfr.ab_vec_count; ++i) {
	  unsigned char md[SHA_DIGEST_LENGTH];
	  SHA1((const unsigned char*)vecs[i].ab_address, vecs[i].ab_len, md);
	  printf("\toffset: %d, len: %d\n", vecs[i].ab_offset, vecs[i].ab_len);
	  printf("\tSHA1: ");
	  int c;
	  for (c=0; c < SHA_DIGEST_LENGTH ;++c) {
	    printf("%x", (int)md[c]);
	  }
	  printf("\n");
	}
      } else {
	for (i=0; i<xfr.ab_vec_count; ++i) {
	  printf("\toffset: %d, len: %d\n\n", vecs[i].ab_offset, vecs[i].ab_len);
	  vecs[i].ab_address = (__u64)malloc(vecs[i].ab_len);
	  // FIXME: currently it behave like /dev/zero
	  memset((char*)vecs[i].ab_address, 0, vecs[i].ab_len);
	}
	ioctl(fd, ABUSE_PUT_REQ, &xfr);
      }
      for (i=0; i<xfr.ab_vec_count; ++i)
	free((struct abuse_vec*)vecs[i].ab_address);
      free(vecs);
      fds[0].revents = 0;
      printf("\n");
    }

    // got signal! closing
    if (fds[1].revents)
      break;
  }

  fprintf(stderr, "Exiting\n");
  teardown();
  close(fd);
  return 0;
}
