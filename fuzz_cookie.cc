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
  if(size < 1)
    return 0;

  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  /* Enable the cookie engine */
  curl_easy_setopt(easy, CURLOPT_COOKIEFILE, "");

  /* Split input into multiple cookie-list entries by newline; pass each
   * to CURLOPT_COOKIELIST which routes to the cookie parser, accepting
   * both "Set-Cookie:" header form and Netscape cookie-file form. */
  const char *p = (const char *)data;
  const char *end = p + size;
  while(p < end) {
    const char *eol = (const char *)memchr(p, '\n', end - p);
    size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
    if(linelen) {
      char *line = (char *)malloc(linelen + 1);
      if(line) {
        memcpy(line, p, linelen);
        line[linelen] = 0;
        curl_easy_setopt(easy, CURLOPT_COOKIELIST, line);
        free(line);
      }
    }
    if(!eol)
      break;
    p = eol + 1;
  }

  /* Pull out the in-memory cookie list to exercise the serializer. */
  struct curl_slist *list = NULL;
  curl_easy_getinfo(easy, CURLINFO_COOKIELIST, &list);
  curl_slist_free_all(list);

  /* Trigger flush/cleanup paths. */
  curl_easy_setopt(easy, CURLOPT_COOKIELIST, "FLUSH");
  curl_easy_setopt(easy, CURLOPT_COOKIELIST, "RELOAD");
  curl_easy_setopt(easy, CURLOPT_COOKIELIST, "ALL");
  curl_easy_setopt(easy, CURLOPT_COOKIELIST, "SESS");

  curl_easy_cleanup(easy);
  return 0;
}
