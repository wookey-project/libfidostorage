/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
#ifndef LIBFIDOSTORAGE_H_
#define LIBFIDOSTORAGE_H_


#define MAX_APPID_TABLE_LEN 4000000UL /* 4MB */

typedef enum {
    ICON_TYPE_IMAGE = 0,
    ICON_TYPE_COLOR = 1,
} fidostorage_icon_type_t;

typedef union {
    uint8_t rgb_color[3];
    uint8_t icon[0]; /* null-sized */
} fidostorage_icon_data_t;

typedef struct __packed {
    uint8_t      hmac[64];
    uint8_t      appid[32];
    uint32_t     ctr;
    uint8_t      icon_type;
    uint16_t     icon_len;
    /* when setting new apid, there is no need to specify the icon content in case of icon image,
     * as the icon image is already set in the SDCard. In case of icon color, use the
     * rgb field of the union. */
    fidostorage_icon_data_t  icon;
} fidostorage_appid_metadata_t;


mbed_error_t    fidostorage_configure(uint8_t *black_buf, uint8_t *red_buf, uint16_t  buflen);

mbed_error_t    fidostorage_get_appid_slot(uint8_t* appid, uint32_t *slot);

mbed_error_t    fidostorage_set_appid_slot(uint8_t*appid);

mbed_error_t    fidostorage_get_appid_metadata(uint8_t const * const appid, uint32_t    appid_slot, uint8_t *data_buffer);

mbed_error_t    fidostorage_set_appid_metada(uint8_t *appid, uint32_t   appid_slot, fidostorage_appid_metadata_t const * const metadata);

#endif/*!LIBFIDOSTORAGE_H_*/
