#ifndef SD_ENC_H_
#define SD_ENC_H_

#include "autoconf.h"
#include "libc/types.h"
#include "api/libfidostorage.h"
#include "fidostorage.h"

/* Declare low level stuff */
mbed_error_t  sd_enc_declare(void);

/*
 * Set the SD AES-CBC-ESSIV encryption master key.
 */
mbed_error_t set_encrypted_SD_key(const uint8_t *key, uint32_t key_len);

/* Read encrypted data from a sector_number and put the decrypted data in the buffer.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t read_encrypted_SD_crypto_sectors(uint8_t *buff_out, uint32_t buff_len, uint32_t sector_num);

/* Write clear data from the input buffer and put encrypted data on SD from sector_number.
 * Note: the sector number is a "cryptographic" sector of 4096 bytes.
 */
mbed_error_t write_encrypted_SD_crypto_sectors(const uint8_t *buff_in, uint32_t buff_len, uint32_t sector_num);


#endif /* SD_ENC_H_ */
