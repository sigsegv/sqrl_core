/*
 
 https://github.com/superwills/NibbleAndAHalf
 base64.h -- Fast base64 encoding and decoding.
 version 1.0.0, April 17, 2013 143a
 
 Copyright (C) 2013 William Sherif
 
 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.
 
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 
 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software. If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.
 
 William Sherif
 will.sherif@gmail.com
 
 YWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz
 
 */

/*
 Modified to be SQRL complient base64url encoded
 So encoding does not pad with "=", but decoding does expect it.
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "strbuf.h"

void sqrl_base64(sqrl_strbuf_t *out, const void *buf, size_t buf_len);

void sqrl_unbase64(sqrl_buffer_t *out, const char *ascii, size_t ascii_len);

// Converts binary data of length=len to base64 characters.
// Length of the resultant string is stored in flen
// (you must pass pointer flen).
char* base64( const void* binaryData, size_t len, size_t *flen );

unsigned char* unbase64( const char* ascii, size_t len, size_t *flen );

#endif
