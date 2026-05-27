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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(size < 1)
    return 0;

  /* Write the fuzz blob to a temp file and feed it to the netrc parser. */
  char tpath[] = "/tmp/netrc_fuzz_XXXXXX";
  int fd = mkstemp(tpath);
  if(fd < 0)
    return 0;
  if(write(fd, data, size) >= 0) {}
  close(fd);

  CURL *easy = curl_easy_init();
  if(easy) {
    curl_easy_setopt(easy, CURLOPT_NETRC, (long)CURL_NETRC_REQUIRED);
    curl_easy_setopt(easy, CURLOPT_NETRC_FILE, tpath);

    /* Curl_parsenetrc is called from url.c during connection setup once a
       hostname is known. Numeric 0.0.0.0:1 keeps the resolver out of the
       loop; the 1 ms timeouts bound the perform call. */
    curl_easy_setopt(easy, CURLOPT_URL, "http://0.0.0.0:1/");
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 1L);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 1L);
    curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
    curl_easy_perform(easy);

    curl_easy_cleanup(easy);
  }

  unlink(tpath);
  return 0;
}
