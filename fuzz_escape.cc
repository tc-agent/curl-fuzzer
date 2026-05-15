/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(!size || size > 8192)
    return 0;

  /* curl_easy_escape needs an explicit non-zero length so it does not
     fall back to strlen() on a buffer that is not NUL-terminated. */
  char *enc = curl_easy_escape(NULL, (const char *)data, (int)size);
  if(enc) {
    int decoded_len = 0;
    char *dec = curl_easy_unescape(NULL, enc, (int)strlen(enc), &decoded_len);
    if(dec)
      curl_free(dec);
    curl_free(enc);
  }

  /* Drive unescape directly on raw input with explicit length. */
  int dl = 0;
  char *dec2 = curl_easy_unescape(NULL, (const char *)data, (int)size, &dl);
  if(dec2)
    curl_free(dec2);
  return 0;
}
