
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bvm/bvm.h"
#include "log.h"

typedef struct bvm_dev_mem_fp_s {
  uint8_t* mem;
  size_t size;
  bool freemem; /* true if memory should be freed on close */
} bvm_dev_mem_fp_t;

size_t _bvm_dev_mem_get_size(bvm_dev_t* dev) {
  bvm_dev_mem_fp_t* devfp = (bvm_dev_mem_fp_t*)dev->user;
  return devfp->mem != NULL ? devfp->size : 0;
}

ssize_t _bvm_dev_mem_get_blocksize(bvm_dev_t* dev) {
  if (dev->user == NULL) {
    return 0;
  }
  return 1024 * 4;
}

bvm_errcode_t _bvm_dev_mem_close(bvm_dev_t* dev) {
  bvm_dev_mem_fp_t* devfp = (bvm_dev_mem_fp_t*)dev->user;
  if (devfp == NULL) {
    return BVM_ERROR_DEVICE_CLOSED;
  }

  if (devfp->freemem && devfp->mem != NULL) {
    free(devfp->mem);
  }

  free(devfp);
  dev->user = NULL;
  return BVM_OK;
}

ssize_t _bvm_dev_mem_read(bvm_dev_t* dev, void* buf, size_t nbyte,
                          size_t offset) {
  bvm_dev_mem_fp_t* devfp = (bvm_dev_mem_fp_t*)dev->user;

  if (offset >= devfp->size) {
    return -1;
  }

  if ((nbyte + offset) > devfp->size) {
    nbyte = devfp->size - offset;
  }

  memcpy(buf, &devfp->mem[offset], nbyte);

  return nbyte;
}

ssize_t _bvm_dev_mem_write(bvm_dev_t* dev, const void* buf, size_t nbyte,
                           size_t offset) {
  bvm_dev_mem_fp_t* devfp = (bvm_dev_mem_fp_t*)dev->user;

  if (offset >= devfp->size) {
    return -1;
  }

  if ((nbyte + offset) > devfp->size) {
    nbyte = devfp->size - offset;
  }

  memcpy(&devfp->mem[offset], buf, nbyte);

  return nbyte;
}

bvm_errcode_t _bvm_dev_mem_flush(bvm_dev_t* dev) {
  (void)dev; /* unused */
  return BVM_OK;
}

const char* const BVM_DEV_MEM_NAME = "bvm_dev_mem";
static bvm_dev_ops_t bvm_dev_mem_ops = {
    .name = BVM_DEV_MEM_NAME,
    .get_size = _bvm_dev_mem_get_size,
    .get_blocksize = _bvm_dev_mem_get_blocksize,
    .close = _bvm_dev_mem_close,
    .read = _bvm_dev_mem_read,
    .write = _bvm_dev_mem_write,
    .flush = _bvm_dev_mem_flush,
};

bvm_dev_t* bvm_dev_memopen(void* mem, size_t size) {
  bool freemem = false;
  if (mem == NULL && size > 0) {
    freemem = true;
    mem = calloc(1, size);
    if (mem == NULL) {
      fprintf(stderr,
              "bvm_dev_memopen: failed to allocate memory for device buffer\n");
      return NULL;
    }
  }

  bvm_dev_mem_fp_t* devfp =
      (bvm_dev_mem_fp_t*)calloc(1, sizeof(bvm_dev_mem_fp_t));
  if (devfp == NULL) {
    fprintf(stderr, "bvm_dev_memopen: failed to allocate memory for devfp\n");
    if (freemem) {
      free(mem);
    }
    return NULL;
  }

  devfp->mem = mem;
  devfp->size = size;
  devfp->freemem = freemem;

  bvm_dev_t* dev = bvm_dev_create(bvm_dev_mem_ops, devfp);
  if (dev == NULL) {
    if (freemem) {
      free(mem);
    }
    free(devfp);
    return NULL;
  }
  return dev;
}

