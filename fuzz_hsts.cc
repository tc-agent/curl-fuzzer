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

struct hsts_feed {
  const uint8_t *data;
  size_t size;
  size_t offset;
};

/* Feed HSTS entries to libcurl one line at a time. */
static CURLSTScode hsts_read_cb(CURL *easy,
                                struct curl_hstsentry *e,
                                void *userp)
{
  (void)easy;
  struct hsts_feed *f = (struct hsts_feed *)userp;
  if(f->offset >= f->size)
    return CURLSTS_DONE;

  const uint8_t *p = f->data + f->offset;
  const uint8_t *end = f->data + f->size;
  const uint8_t *eol = (const uint8_t *)memchr(p, '\n', end - p);
  size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
  size_t namelen = linelen < e->namelen - 1 ? linelen : e->namelen - 1;
  memcpy(e->name, p, namelen);
  e->name[namelen] = 0;
  e->includeSubDomains = (namelen && (p[0] & 1)) ? 1 : 0;
  /* Provide a fixed-format expiry to exercise the date parser path. */
  snprintf(e->expire, sizeof(e->expire), "20370101 00:00:00");
  f->offset += linelen + (eol ? 1 : 0);
  return CURLSTS_OK;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(size < 1)
    return 0;

  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  struct hsts_feed f = { data, size, 0 };
  curl_easy_setopt(easy, CURLOPT_HSTS_CTRL, (long)CURLHSTS_ENABLE);
  curl_easy_setopt(easy, CURLOPT_HSTSREADFUNCTION, hsts_read_cb);
  curl_easy_setopt(easy, CURLOPT_HSTSREADDATA, &f);

  /* Also drive the file parser via a temp file with the same fuzzed bytes. */
  char tpath[] = "/tmp/hsts_fuzz_XXXXXX";
  int fd = mkstemp(tpath);
  if(fd >= 0) {
    if(write(fd, data, size) >= 0) {}
    close(fd);
    curl_easy_setopt(easy, CURLOPT_HSTS, tpath);
  }

  /* curl_easy_perform pulls Curl_pretransfer which is what kicks both the
     read-callback and the file loader. Numeric 0.0.0.0:1 avoids the DNS
     resolver entirely; the 1 ms timeouts bound the perform call. */
  curl_easy_setopt(easy, CURLOPT_URL, "http://0.0.0.0:1/");
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 1L);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 1L);
  curl_easy_setopt(easy, CURLOPT_NOBODY, 1L);
  curl_easy_perform(easy);

  curl_easy_cleanup(easy);
  if(fd >= 0)
    unlink(tpath);
  return 0;
}
