#ifndef FIDOSTORAGE_H_
#define FIDOSTORAGE_H_


#include "autoconf.h"
#include "libc/types.h"
#include "libc/random.h"
#include "libc/string.h"
#include "libc/stdio.h"
#include "libc/sync.h"
#include "libc/random.h"
#include "libc/arpa/inet.h"
#include "hmac.h"
#include "aes.h"

#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

typedef struct {
    uint8_t     *buf;
    uint16_t     buflen;
    uint8_t      iv[16]; /* do we consider CTR with incremental iv=0 for slot=0 ? */
    uint8_t      key[32];
    uint8_t      key_h[32];
    uint32_t     key_len;
    aes_context  aes_ctx; /* aes context */
    bool         configured;
    /* in case of CRYP with DMA usage */
    bool       dma_in_finished;
    bool       dma_out_finished;
    int        dma_in_desc;
    int        dma_out_desc;
    //
    dma_shm_t dmashm_rd;
    dma_shm_t dmashm_wr;
} fidostorage_ctx_t;



bool fidostorage_is_configured(void);

fidostorage_ctx_t *fidostorage_get_context(void);

#endif/*!FIDOSTORAGE_H_*/
