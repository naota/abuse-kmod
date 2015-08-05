#include <sys/types.h>

struct abuse_operations {
  void* (*address)(off_t offset, size_t len, int read, void *userdata);
  //void* (*read)(off_t offset, size_t len, void *userdata);
  void  (*read_complete)(off_t offset, size_t len, void *userdata);
  //void* (*write)(off_t offset, size_t len, void *userdata);
  void  (*write_complete)(off_t offset, size_t len, void *userdata);
  const size_t size;
};

int abuse_main(const char *abuse_dev, struct abuse_operations *aops, void *userdata);
