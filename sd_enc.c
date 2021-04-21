#include "autoconf.h"
#include "libc/types.h"
#include "libc/string.h"
#include "libc/stdio.h"
#include "libc/sync.h"
#include "libc/arpa/inet.h"
#include "aes.h"
#include "hmac.h"
#include "libsd.h"
#include "libcryp.h"
#include "sd_enc.h"

#ifdef CONFIG_USR_LIB_FIDOSTORAGE_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

/* A "cryptographic" sector size */
#define CRYPTO_SECTOR_SIZE 4096
#define SD_SECTOR_SIZE 512


/**************************** DO NOT USE SD ENCRYPTION ****************************/
#ifndef CONFIG_USR_LIB_FIDOSTORAGE_SD_ENCRYPTION 

mbed_error_t sd_enc_declare(void) {
    return MBED_ERROR_NONE;
}

mbed_error_t set_encrypted_SD_key(const uint8_t *key __attribute__((unused)), uint32_t key_len __attribute__((unused)))
{
    return MBED_ERROR_NONE;
}

/* Read encrypted data from a sector_number and put the decrypted data in the buffer.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t read_encrypted_SD_crypto_sectors(uint8_t *buff_out, uint32_t buff_len, uint32_t sector_num)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    int ret;
    if ((ret = sd_read((uint32_t*)buff_out, sector_num*8, buff_len)) != SD_SUCCESS) {
        log_printf("[fidostorage] Failed during SD_read, from sector %d, %d words to be read: ret=%d\n", sector_num * (CRYPTO_SECTOR_SIZE / SD_SECTOR_SIZE), buff_len, ret);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
err:
    return errcode;
}

/* Write clear data from the input buffer and put encrypted data on SD from sector_number.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t write_encrypted_SD_crypto_sectors(const uint8_t *buff_in, uint32_t buff_len, uint32_t sector_num)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    int ret;
    if ((ret = sd_write((uint32_t*)buff_in, sector_num*8, buff_len)) != SD_SUCCESS) {
        log_printf("[fidostorage] Failed during SD_write, to sector %d, %d words to be write: ret=%d\n", sector_num * (CRYPTO_SECTOR_SIZE / SD_SECTOR_SIZE), buff_len, ret);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
err:
    return errcode;
}

/**************************** USE SD ENCRYPTION **********************************/
#else

/* CRYP DMA callback routines */
static void dma_in_complete(uint8_t irq __attribute__((unused)), uint32_t status __attribute__((unused))) {
    ctx.dma_in_finished = true;
    request_data_membarrier();
}
static void dma_out_complete(uint8_t irq __attribute__((unused)), uint32_t status __attribute__((unused))) {
    ctx.dma_out_finished = true;
    request_data_membarrier();
}
/* CRYP DMA descriptors */
static volatile int dma_in_desc, dma_out_desc;

/* Declare low level stuff */
mbed_error_t sd_enc_declare(void)
{
	mbed_error_t errcode = MBED_ERROR_NONE;
	errcode = cryp_early_init(true, CRYP_MAP_AUTO, CRYP_CFG, &dma_in_desc, &dma_out_desc);
	request_data_membarrier();
	return errcode;
}


/*
 * AES-CBC-ESSIV derive IV from a sector.
 */
static mbed_error_t aes_cbc_essiv_derive_iv(uint32_t sector, uint8_t *key_h, uint32_t key_h_len, uint8_t *iv, uint32_t iv_len)
{
	mbed_error_t errcode = MBED_ERROR_NONE;
	aes_context  aes_ctx;

	if((key_h == NULL) || (key_h_len != 32) || (iv == NULL) || (iv_len != 16)){
		errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	
	/* Put the sector in a big endian format */
	uint32_t big_endian_sector_number = htonl(sector);
	/* marshaling from uint32 to u[4] buffer */
	uint8_t sector_number_buff[16] = { 0 };

	sector_number_buff[0] = (big_endian_sector_number >> 0) & 0xff;
	sector_number_buff[1] = (big_endian_sector_number >> 8) & 0xff;
	sector_number_buff[2] = (big_endian_sector_number >> 16) & 0xff;
	sector_number_buff[3] = (big_endian_sector_number >> 24) & 0xff;

	/* Now create the ESSIV IV from sector number */
	if (aes_init(&aes_ctx, key_h, AES256, NULL, ECB, AES_ENCRYPT, AES_SOFT_UNMASKED, NULL, NULL, -1, -1)) {
		errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}
	/* and encrypt sector in AES-ECB */
	if (aes_exec(&aes_ctx, sector_number_buff, iv, iv_len, -1, -1)) {
		errcode = MBED_ERROR_UNKNOWN;
		goto err;
	}

err:
	return errcode;	
}


/* AES-CBC-ESSIV master key      */
static uint8_t AES_CBC_ESSIV_key[32]  = { 0 };
/* AES-CBC-ESSIV master key hash */
static uint8_t AES_CBC_ESSIV_hkey[32] = { 0 };


/**********************/
static uint32_t SD_capacity = 0;
static int check_SD_overflow(uint32_t sector_num, uint32_t buff_len)
{
	if(SD_capacity == 0){
		SD_capacity = sd_get_capacity();
	}
	/* Sanity check that we do not overflow */
	uint64_t 

}

/*
 * Set the SD AES-CBC-ESSIV encryption master key.
 */
mbed_error_t set_encrypted_SD_key(const uint8_t *key, uint32_t key_len)
{
	mbed_error_t errcode = MBED_ERROR_NONE;
	sha256_context sha256_ctx;

	if((key == NULL) || (key_len != sizeof(AES_CBC_ESSIV_key))){
		errcode = MBED_ERROR_INVPARAM;
		goto err;
	}

	/* Copy the provided key in buffer */
	memcpy(AES_CBC_ESSIV_key, key, sizeof(AES_CBC_ESSIV_key));
	/* Compute the hash and store it in buffer */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, key, key_len);
	sha256_final(&sha256_ctx, AES_CBC_ESSIV_hkey);

err:
	return errcode;
}

/* Read encrypted data from a sector_number and put the decrypted data in the buffer.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t read_encrypted_SD_crypto_sectors(uint8_t *buff_out, uint32_t buff_len, uint32_t sector_num)
{
	mbed_error_t errcode = MBED_ERROR_NONE;
	/* Sanity checks */
	if(buff_out == NULL){
		errcode = MBED_ERROR_INVPARAM;
		goto err;
	}
	if(SD_capacity == 0){
		SD_capacity = sd_get_capacity();
	}

err:
	return errcode;
}

/* Write clear data from the input buffer and put encrypted data on SD from sector_number.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t write_encrypted_SD_crypto_sectors(const uint8_t *buff_in, uint32_t buff_len, uint32_t sector_num)
{
	mbed_error_t errcode = MBED_ERROR_NONE;
	/* Sanity checks */
	if(buff_in == NULL){
		errcode = MBED_ERROR_INVPARAM;
		goto err;
	}

err:
	return errcode;
}

#endif /* CONFIG_USR_LIB_FIDOSTORAGE_SD_ENCRYPTION */
