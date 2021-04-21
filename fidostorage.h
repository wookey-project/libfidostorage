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

#endif/*!FIDOSTORAGE_H_*/
