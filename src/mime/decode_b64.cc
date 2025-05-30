//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// decode_b64.cc author Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "decode_b64.h"

#include "utils/util_unfold.h"

#include "decode_buffer.h"

using namespace snort;

void B64Decode::reset_decode_state()
{
    reset_decoded_bytes();
    buffer->reset_saved();
}

DecodeResult B64Decode::decode_data(const uint8_t* start, const uint8_t* end, uint8_t* decode_buf)
{
    uint32_t act_encode_size = 0, act_decode_size = 0;
    uint32_t i = 0;

    if (!buffer->check_restore_buffer() || !decode_buf)
    {
        reset_decode_state();
        return DECODE_EXCEEDED;
    }

    uint32_t encode_avail = buffer->get_encode_avail() - buffer->get_prev_encoded_bytes();

    if (sf_strip_CRLF(start, (end-start), buffer->get_encode_buff() + buffer->get_prev_encoded_bytes(),
        encode_avail, &act_encode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    act_encode_size = act_encode_size + buffer->get_prev_encoded_bytes();

    i = (act_encode_size)%4;

    /* Encoded data should be in multiples of 4. Then we need to wait for the remainder encoded data to
     * successfully decode the base64 data. This happens when base64 data is spanned across packets*/
    if (i)
    {
        act_encode_size = act_encode_size - i;
        buffer->save_buffer(buffer->get_encode_buff() + act_encode_size, i);
    }
    else
        buffer->reset_saved();

    if (sf_base64decode(buffer->get_encode_buff(), act_encode_size,
        decode_buf, buffer->get_decode_avail(), &act_decode_size) != 0)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }
    else if (!act_decode_size && !encode_avail)
    {
        reset_decode_state();
        return DECODE_FAIL;
    }

    decoded_bytes = act_decode_size;
    decodePtr = decode_buf;
    buffer->update_buffer(act_encode_size, act_decode_size);
    decode_bytes_read = buffer->get_decode_bytes_read();
    return DECODE_SUCCESS;
}

B64Decode::B64Decode(int max_depth, int detect_depth) : DataDecode(max_depth, detect_depth)
{
    buffer = new DecodeBuffer(max_depth);
}

B64Decode::~B64Decode()
{
    if (buffer)
        delete buffer;
}

uint8_t sf_decode64tab[256] =
{
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,62,100,100,100, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,100,100,100, 99,100,100,
    100,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,100,100,100,100,100,
    100, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,
    100,100,100,100,100,100,100,100,100,100,100,100,100,100,100,100
};

namespace snort
{
/* base64decode assumes the input data terminates with '=' and/or at the end of the input buffer
 * at inbuf_size.  If extra characters exist within inbuf before inbuf_size is reached, it will
 * happily decode what it can and skip over what it can't.  This is consistent with other decoders
 * out there.  So, either terminate the string, set inbuf_size correctly, or at least be sure the
 * data is valid up until the point you care about.  Note base64 data does NOT have to end with
 * '=' and won't if the number of bytes of input data is evenly divisible by 3.
*/
int sf_base64decode(uint8_t* inbuf, uint32_t inbuf_size, uint8_t* outbuf, uint32_t outbuf_size,
    uint32_t* bytes_written)
{
    uint8_t* cursor, * endofinbuf;
    uint8_t* outbuf_ptr;
    uint8_t base64data[4], * base64data_ptr; /* temporary holder for current base64 chunk */
    uint8_t tableval_a, tableval_b, tableval_c, tableval_d;

    uint32_t n;
    uint32_t max_base64_chars; /* The max number of decoded base64 chars that fit into outbuf */

    int error = 0;

    /* This algorithm will waste up to 4 bytes but we really don't care.
       At the end we're going to copy the exact number of bytes requested. */
    max_base64_chars = (outbuf_size / 3) * 4 + 4; /* 4 base64 bytes gives 3 data bytes, plus
                                                    an extra 4 to take care of any rounding */

    base64data_ptr = base64data;
    endofinbuf = inbuf + inbuf_size;

    /* Strip non-base64 chars from inbuf and decode */
    n = 0;
    *bytes_written = 0;
    cursor = inbuf;
    outbuf_ptr = outbuf;
    while ((cursor < endofinbuf) && (n < max_base64_chars))
    {
        if (sf_decode64tab[*cursor] != 100)
        {
            *base64data_ptr++ = *cursor;
            n++; /* Number of base64 bytes we've stored */
            if (!(n % 4))
            {
                /* We have four databytes upon which to operate */

                if ((base64data[0] == '=') || (base64data[1] == '='))
                {
                    /* Error in input data */
                    error = 1;
                    break;
                }

                /* retrieve values from lookup table */
                tableval_a = sf_decode64tab[base64data[0]];
                tableval_b = sf_decode64tab[base64data[1]];
                tableval_c = sf_decode64tab[base64data[2]];
                tableval_d = sf_decode64tab[base64data[3]];

                if (*bytes_written < outbuf_size)
                {
                    *outbuf_ptr++ = (tableval_a << 2) | (tableval_b >> 4);
                    (*bytes_written)++;
                }

                if ((base64data[2] != '=') && (*bytes_written < outbuf_size))
                {
                    *outbuf_ptr++ = (tableval_b << 4) | (tableval_c >> 2);
                    (*bytes_written)++;
                }
                else
                {
                    break;
                }

                if ((base64data[3] != '=') && (*bytes_written < outbuf_size))
                {
                    *outbuf_ptr++ = (tableval_c << 6) | tableval_d;
                    (*bytes_written)++;
                }
                else
                {
                    break;
                }

                /* Reset our decode pointer for the next group of four */
                base64data_ptr = base64data;
            }
        }
        cursor++;
    }

    if (error)
        return(-1);
    else
        return(0);
}
} // namespace snort

