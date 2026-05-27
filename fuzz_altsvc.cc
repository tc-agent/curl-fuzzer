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

  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  /* Write the fuzz blob to a temp file and feed it to the alt-svc
     file-parser. Setting CURLOPT_ALTSVC triggers Curl_altsvc_load()
     synchronously from lib/setopt.c, so no perform is needed for the
     parser to run. */
  char tpath[] = "/tmp/altsvc_fuzz_XXXXXX";
  int fd = mkstemp(tpath);
  if(fd < 0) {
    curl_easy_cleanup(easy);
    return 0;
  }
  if(write(fd, data, size) >= 0) {}
  close(fd);

  curl_easy_setopt(easy, CURLOPT_ALTSVC_CTRL,
                   (long)(CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3));
  curl_easy_setopt(easy, CURLOPT_ALTSVC, tpath);

  /* A short-circuiting perform also exercises the alt-svc save path during
     teardown plus the surrounding easy/multi state machine. The numeric
     0.0.0.0:1 URL keeps the loop off the resolver. */
  curl_easy_setopt(easy, CURLOPT_URL, "http://0.0.0.0:1/");
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 1L);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 1L);
  curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
  curl_easy_perform(easy);

  curl_easy_cleanup(easy);
  unlink(tpath);
  return 0;
}
