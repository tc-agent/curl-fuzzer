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

/* Exercise the URL API more thoroughly than the existing fuzz_url:
 * - parse two strings (base + relative)
 * - set/get every CURLUPART_*
 * - encode/decode/idn flags
 * - clone path
 */

static const CURLUPart parts[] = {
  CURLUPART_URL, CURLUPART_SCHEME, CURLUPART_USER, CURLUPART_PASSWORD,
  CURLUPART_OPTIONS, CURLUPART_HOST, CURLUPART_PORT, CURLUPART_PATH,
  CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_ZONEID,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(size < 2)
    return 0;

  FuzzedDataProvider fdp(data, size);

  CURLU *uh = curl_url();
  if(!uh)
    return 0;

  /* First string: base URL with GUESS_SCHEME */
  std::string base = fdp.ConsumeRandomLengthString(2048);
  curl_url_set(uh, CURLUPART_URL, base.c_str(),
               CURLU_GUESS_SCHEME | CURLU_NON_SUPPORT_SCHEME |
               CURLU_URLENCODE | CURLU_DEFAULT_SCHEME);

  /* Second string: maybe a relative URL */
  if(fdp.ConsumeBool()) {
    std::string rel = fdp.ConsumeRandomLengthString(1024);
    curl_url_set(uh, CURLUPART_URL, rel.c_str(),
                 CURLU_DEFAULT_SCHEME | CURLU_APPENDQUERY);
  }

  /* Set various parts. */
  int nset = fdp.ConsumeIntegralInRange(0, 5);
  for(int i = 0; i < nset && fdp.remaining_bytes() > 0; i++) {
    int pidx = fdp.ConsumeIntegralInRange(0, (int)(sizeof(parts)/sizeof(parts[0]) - 1));
    std::string v = fdp.ConsumeRandomLengthString(256);
    unsigned int flags = fdp.ConsumeBool() ? CURLU_URLENCODE : 0;
    flags |= fdp.ConsumeBool() ? CURLU_APPENDQUERY : 0;
    flags |= fdp.ConsumeBool() ? CURLU_NON_SUPPORT_SCHEME : 0;
    curl_url_set(uh, parts[pidx], v.c_str(), flags);
  }

  /* Read every part back. */
  for(unsigned i = 0; i < sizeof(parts)/sizeof(parts[0]); i++) {
    char *out = NULL;
    unsigned int gflags = fdp.ConsumeBool() ? CURLU_URLDECODE : 0;
    gflags |= fdp.ConsumeBool() ? CURLU_DEFAULT_PORT : 0;
    gflags |= fdp.ConsumeBool() ? CURLU_NO_DEFAULT_PORT : 0;
    gflags |= fdp.ConsumeBool() ? CURLU_PUNYCODE : 0;
    gflags |= fdp.ConsumeBool() ? CURLU_PUNY2IDN : 0;
    if(curl_url_get(uh, parts[i], &out, gflags) == CURLUE_OK)
      curl_free(out);
  }

  /* Dup, then free dup. */
  CURLU *dup = curl_url_dup(uh);
  curl_url_cleanup(dup);

  /* Clear parts. */
  if(fdp.ConsumeBool())
    curl_url_set(uh, CURLUPART_QUERY, NULL, 0);

  curl_url_cleanup(uh);
  return 0;
}
