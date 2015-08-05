#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include "abuse.h"
#include "libabuse.h"

#define __USE_GNU
#include <poll.h>

const char *ABCTL_PATH = "/dev/abctl";
const int FDCNT = 2;
const int BIO_MAX_PAGES = 256;

struct dev_info {
  int ctlfd;
  int devfd;
};

void teardown(struct dev_info *info)
{
  ioctl(info->ctlfd, ABUSE_RESET);
  ioctl(info->ctlfd, ABUSE_RELEASE);
  close(info->devfd);
  close(info->devfd);
  return;
}

int open_device(struct dev_info *dinfo, const char *abuse_dev, struct abuse_operations *aops)
{
  int fd = open(ABCTL_PATH, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s: %s\n", ABCTL_PATH, strerror(errno));
    return -1;
  }

  int devfd = open(abuse_dev, O_RDWR);
  if (devfd < 0) {
    fprintf(stderr, "Failed to open %s: %s\n", abuse_dev, strerror(errno));
    return -1;
  }

  if (ioctl(fd, ABUSE_ACQUIRE, devfd) == -1)  {
    perror("ioctl(ABUSE_ACQUIRE) failed");
    return -1;
  }

  // check if disk is already there
  struct abuse_info ainfo;
  if (ioctl(fd, ABUSE_GET_STATUS, &ainfo) == -1) {
    perror("GET_STATUS failed");
    return -1;
  }
  if (ainfo.ab_size > 0)
    ioctl(fd, ABUSE_RESET);

  // Generate disk
  ainfo.ab_size = aops->size;
  ainfo.ab_blocksize = 4096;
  ainfo.ab_max_queue = 0;
  if (ioctl(fd, ABUSE_SET_STATUS, &ainfo) == -1) {
    perror("SET_STATUS failed");
    return -1;
  }

  dinfo->ctlfd = fd;
  dinfo->devfd = devfd;

  return 0;
}

int setsignal(struct dev_info *info, struct pollfd *fds)
{
  sigset_t sigmask;

  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGINT);
  sigaddset(&sigmask, SIGTERM);
  sigaddset(&sigmask, SIGQUIT);

  fds[0].fd = info->ctlfd;
  fds[0].events = POLLMSG;
  fds[1].fd = signalfd(-1, &sigmask, 0);
  fds[1].events = POLLIN;

  if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
    perror("sigprocmask failed");
    return -1;
  }

  return 0;
}

int abuse_main(const char *abuse_dev, struct abuse_operations *aops, void *userdata)
{
  int ret;
  struct dev_info info;
  struct pollfd fds[FDCNT];

  //if (aops->read == NULL || aops->write == NULL)
  //return EINVAL;

  memset(&info, 0, sizeof(info));

  if ((ret = open_device(&info, abuse_dev, aops))) {
    goto out;
  }

  if ((ret = setsignal(&info, fds))) {
    goto out;
  }

  // main loop waiting for IO
  while (ppoll(fds, FDCNT, NULL, NULL) > 0) {
    // got signal! closing
    if (fds[1].revents)
      break;

    if (fds[0].revents) {
      struct abuse_xfr_hdr xfr;
      struct abuse_vec vecs[BIO_MAX_PAGES];

      for(;;) {
	__u32 i;
	memset(&xfr, 0, sizeof(xfr));
	xfr.ab_transfer_address = (__u64) vecs;

	// read header
	if (ioctl(info.ctlfd, ABUSE_GET_REQ, &xfr) == -1) {
	  if (errno != ENOMSG) {
	    ret = errno;
	    perror("ioctl(ABUSE_GET_BIO) failed");
	    goto out;
	  }
	}

	if (xfr.ab_vec_count == 0)
	  break;
	if (xfr.ab_vec_count > BIO_MAX_PAGES)
	  break;

	// allocate receive/send buffer
	off_t  off = xfr.ab_sector * 512;
	size_t len = 0;
	for (i=0; i<xfr.ab_vec_count; ++i) {
	  len += vecs[i].ab_len;
	}

	int read = xfr.ab_command == 0;
	void *data = aops->address(off, len, read, userdata);;

	size_t pos = 0;
	for (i=0; i<xfr.ab_vec_count; ++i) {
	  vecs[i].ab_address = (__u64)(data + pos);
	  pos += vecs[i].ab_len;
	}

	if (ioctl(info.ctlfd, ABUSE_PUT_REQ, &xfr) == -1) {
	  ret = errno;
	  perror("ioctl(ABUSE_PUT_BIO) failed");
	  goto out;
	}

	if (read && aops->read_complete) {
	  aops->read_complete(off, len, userdata);
	} else if (!read && aops->write_complete) {
	  aops->write_complete(off, len, userdata);
	}
      }

      fds[0].revents = 0;
    }
  }

 out:
  teardown(&info);
  return ret;
}
