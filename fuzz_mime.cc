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
#include <fuzzer/FuzzedDataProvider.h>

static const char *encoders[] = {
  "binary", "8bit", "7bit", "base64", "quoted-printable", nullptr,
};

/* Pull a NUL-terminated string from the fuzzer, with bounded length. */
static char *pull_str(FuzzedDataProvider &fdp, size_t max)
{
  std::string s = fdp.ConsumeRandomLengthString(max);
  return strdup(s.c_str());
}

static void build_part(CURL *easy, FuzzedDataProvider &fdp,
                       curl_mimepart *part, int depth);

static curl_mime *build_mime(CURL *easy, FuzzedDataProvider &fdp, int depth)
{
  curl_mime *mime = curl_mime_init(easy);
  if(!mime)
    return nullptr;

  /* Add 1-4 parts. */
  int n = fdp.ConsumeIntegralInRange(1, 4);
  for(int i = 0; i < n && fdp.remaining_bytes() > 0; i++) {
    curl_mimepart *part = curl_mime_addpart(mime);
    if(!part)
      break;
    build_part(easy, fdp, part, depth);
  }
  return mime;
}

static void build_part(CURL *easy, FuzzedDataProvider &fdp,
                       curl_mimepart *part, int depth)
{
  /* Set name. */
  if(fdp.ConsumeBool()) {
    char *s = pull_str(fdp, 64);
    curl_mime_name(part, s);
    free(s);
  }

  /* Set filename. */
  if(fdp.ConsumeBool()) {
    char *s = pull_str(fdp, 64);
    curl_mime_filename(part, s);
    free(s);
  }

  /* Set type. */
  if(fdp.ConsumeBool()) {
    char *s = pull_str(fdp, 64);
    curl_mime_type(part, s);
    free(s);
  }

  /* Set encoder. */
  if(fdp.ConsumeBool()) {
    int idx = fdp.ConsumeIntegralInRange(0, 4);
    curl_mime_encoder(part, encoders[idx]);
  }

  /* Add custom headers. */
  if(fdp.ConsumeBool()) {
    struct curl_slist *hdrs = NULL;
    int hn = fdp.ConsumeIntegralInRange(1, 3);
    for(int i = 0; i < hn && fdp.remaining_bytes() > 0; i++) {
      char *h = pull_str(fdp, 64);
      hdrs = curl_slist_append(hdrs, h);
      free(h);
    }
    /* takeownership=1: libcurl frees the slist when the mime is freed. */
    curl_mime_headers(part, hdrs, 1);
  }

  /* Add data or subparts. */
  int choice = fdp.ConsumeIntegralInRange(0, 3);
  if(choice == 0) {
    size_t len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
    std::vector<uint8_t> buf = fdp.ConsumeBytes<uint8_t>(len);
    curl_mime_data(part, (const char *)buf.data(), buf.size());
  }
  else if(choice == 1) {
    std::string s = fdp.ConsumeRandomLengthString(256);
    curl_mime_data(part, s.c_str(), CURL_ZERO_TERMINATED);
  }
  else if(choice == 2 && depth < 2) {
    /* Subparts must be built against the same easy handle as the parent,
       since libcurl stores a back-reference to the owning easy in each
       mime node. */
    curl_mime *sub = build_mime(easy, fdp, depth + 1);
    if(sub)
      curl_mime_subparts(part, sub);
  }
  /* choice == 3: no data */
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(size < 1)
    return 0;

  FuzzedDataProvider fdp(data, size);

  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  curl_mime *mime = build_mime(easy, fdp, 0);
  if(mime) {
    /* Attach to handle so the mime tree gets fully validated. */
    curl_easy_setopt(easy, CURLOPT_MIMEPOST, mime);
    curl_mime_free(mime);
  }

  curl_easy_cleanup(easy);
  return 0;
}
