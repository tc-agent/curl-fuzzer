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

/* String options: pulled from curl/curl.h. Each will be set with a fuzzed
 * value — exercising the option dispatcher in lib/setopt.c and the
 * downstream string-validation paths. */
static const CURLoption STR_OPTIONS[] = {
  CURLOPT_URL, CURLOPT_PROXY, CURLOPT_USERAGENT, CURLOPT_REFERER,
  CURLOPT_USERPWD, CURLOPT_PROXYUSERPWD, CURLOPT_COOKIE, CURLOPT_CUSTOMREQUEST,
  CURLOPT_RANGE, CURLOPT_INTERFACE, CURLOPT_KRBLEVEL, CURLOPT_KEYPASSWD,
  CURLOPT_SSL_CIPHER_LIST, CURLOPT_SSLCERT, CURLOPT_SSLKEY,
  /* CURLOPT_SSLENGINE intentionally omitted: it loads an OpenSSL provider
     whose lifecycle is not unwound by curl_easy_cleanup, producing a
     reachable allocation in the leak checker. */
  CURLOPT_CAINFO, CURLOPT_CAPATH, CURLOPT_DNS_INTERFACE, CURLOPT_DNS_LOCAL_IP4,
  CURLOPT_DNS_LOCAL_IP6, CURLOPT_DNS_SERVERS, CURLOPT_ACCEPT_ENCODING,
  CURLOPT_TLSAUTH_USERNAME, CURLOPT_TLSAUTH_PASSWORD,
  CURLOPT_TLSAUTH_TYPE, CURLOPT_TLS13_CIPHERS, CURLOPT_PROXY_SSL_CIPHER_LIST,
  CURLOPT_DEFAULT_PROTOCOL, CURLOPT_SERVICE_NAME, CURLOPT_PROXY_SERVICE_NAME,
  CURLOPT_PINNEDPUBLICKEY, CURLOPT_PROXY_PINNEDPUBLICKEY,
  CURLOPT_NOPROXY, CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER,
  CURLOPT_RTSP_SESSION_ID, CURLOPT_RTSP_STREAM_URI, CURLOPT_RTSP_TRANSPORT,
  CURLOPT_MAIL_FROM, CURLOPT_MAIL_AUTH, CURLOPT_LOGIN_OPTIONS,
  CURLOPT_XOAUTH2_BEARER, CURLOPT_UNIX_SOCKET_PATH, CURLOPT_ABSTRACT_UNIX_SOCKET,
  CURLOPT_PROXY_CAINFO, CURLOPT_PROXY_CAPATH, CURLOPT_PROXY_SSLCERT,
  CURLOPT_PROXY_SSLKEY, CURLOPT_PROXY_KEYPASSWD, CURLOPT_PROXY_TLSAUTH_TYPE,
  CURLOPT_PROXY_TLSAUTH_USERNAME, CURLOPT_PROXY_TLSAUTH_PASSWORD,
  CURLOPT_ALTSVC, CURLOPT_DOH_URL, CURLOPT_SASL_AUTHZID,
  CURLOPT_AWS_SIGV4, CURLOPT_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS_STR,
  CURLOPT_HAPROXY_CLIENT_IP, CURLOPT_ECH, CURLOPT_SSL_SIGNATURE_ALGORITHMS,
};

/* Long options. Many trigger validation logic in setopt.c. */
static const CURLoption LONG_OPTIONS[] = {
  CURLOPT_VERBOSE, CURLOPT_HEADER, CURLOPT_NOPROGRESS, CURLOPT_NOSIGNAL,
  CURLOPT_WILDCARDMATCH, CURLOPT_FAILONERROR, CURLOPT_KEEP_SENDING_ON_ERROR,
  CURLOPT_UPLOAD, CURLOPT_DIRLISTONLY, CURLOPT_APPEND, CURLOPT_NETRC,
  CURLOPT_FOLLOWLOCATION, CURLOPT_UNRESTRICTED_AUTH, CURLOPT_MAXREDIRS,
  CURLOPT_POSTREDIR, CURLOPT_PUT, CURLOPT_POST, CURLOPT_AUTOREFERER,
  CURLOPT_TRANSFERTEXT, CURLOPT_TRANSFER_ENCODING, CURLOPT_TIMEOUT,
  CURLOPT_TIMEOUT_MS, CURLOPT_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_TIME,
  CURLOPT_MAXFILESIZE, CURLOPT_RESUME_FROM, CURLOPT_CRLF, CURLOPT_PORT,
  CURLOPT_HTTPPROXYTUNNEL, CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH,
  CURLOPT_HTTPAUTH, CURLOPT_PROXYTYPE, CURLOPT_HTTP_VERSION,
  CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, CURLOPT_SSLVERSION,
  CURLOPT_PROXY_SSLVERSION, CURLOPT_DNS_USE_GLOBAL_CACHE,
  CURLOPT_DNS_CACHE_TIMEOUT, CURLOPT_BUFFERSIZE, CURLOPT_UPLOAD_BUFFERSIZE,
  CURLOPT_FORBID_REUSE, CURLOPT_FRESH_CONNECT, CURLOPT_CONNECTTIMEOUT,
  CURLOPT_CONNECTTIMEOUT_MS, CURLOPT_IPRESOLVE, CURLOPT_FILETIME,
  CURLOPT_HTTPGET, CURLOPT_TIMECONDITION, CURLOPT_TIMEVALUE,
  CURLOPT_TIMEVALUE_LARGE, CURLOPT_LOCALPORT, CURLOPT_LOCALPORTRANGE,
  CURLOPT_FTP_RESPONSE_TIMEOUT, CURLOPT_FTP_USE_EPSV, CURLOPT_FTP_USE_EPRT,
  CURLOPT_FTP_USE_PRET, CURLOPT_FTP_CREATE_MISSING_DIRS,
  CURLOPT_FTP_FILEMETHOD, CURLOPT_FTP_SKIP_PASV_IP, CURLOPT_FTP_SSL_CCC,
  CURLOPT_USE_SSL, CURLOPT_HTTP_TRANSFER_DECODING,
  CURLOPT_HTTP_CONTENT_DECODING, CURLOPT_NEW_FILE_PERMS,
  CURLOPT_NEW_DIRECTORY_PERMS, CURLOPT_ADDRESS_SCOPE, CURLOPT_CERTINFO,
  CURLOPT_TFTP_BLKSIZE, CURLOPT_TFTP_NO_OPTIONS, CURLOPT_SOCKS5_GSSAPI_NEC,
  CURLOPT_SSL_SESSIONID_CACHE, CURLOPT_SSL_FALSESTART, CURLOPT_SSH_AUTH_TYPES,
  CURLOPT_SSL_OPTIONS, CURLOPT_PROXY_SSL_OPTIONS, CURLOPT_PROXY_SSL_VERIFYPEER,
  CURLOPT_PROXY_SSL_VERIFYHOST, CURLOPT_GSSAPI_DELEGATION, CURLOPT_SSL_ENABLE_ALPN,
  CURLOPT_PIPEWAIT, CURLOPT_STREAM_WEIGHT, CURLOPT_TCP_FASTOPEN,
  CURLOPT_TCP_KEEPALIVE, CURLOPT_TCP_KEEPIDLE, CURLOPT_TCP_KEEPINTVL,
  CURLOPT_TCP_NODELAY, CURLOPT_SUPPRESS_CONNECT_HEADERS, CURLOPT_HAPROXYPROTOCOL,
  CURLOPT_DNS_SHUFFLE_ADDRESSES, CURLOPT_DISALLOW_USERNAME_IN_URL,
  CURLOPT_UPKEEP_INTERVAL_MS, CURLOPT_ALTSVC_CTRL, CURLOPT_MAXAGE_CONN,
  CURLOPT_HSTS_CTRL, CURLOPT_DOH_SSL_VERIFYPEER, CURLOPT_DOH_SSL_VERIFYHOST,
  CURLOPT_DOH_SSL_VERIFYSTATUS, CURLOPT_MAXLIFETIME_CONN,
  CURLOPT_MIME_OPTIONS, CURLOPT_QUICK_EXIT,
  CURLOPT_CA_CACHE_TIMEOUT, CURLOPT_SERVER_RESPONSE_TIMEOUT_MS,
  CURLOPT_TCP_KEEPCNT,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if(size < 2)
    return 0;

  FuzzedDataProvider fdp(data, size);

  CURL *easy = curl_easy_init();
  if(!easy)
    return 0;

  /* Hammer many string options with fuzzed values. */
  int nstrops = sizeof(STR_OPTIONS) / sizeof(STR_OPTIONS[0]);
  int nset_str = fdp.ConsumeIntegralInRange(1, 20);
  for(int i = 0; i < nset_str && fdp.remaining_bytes() > 1; i++) {
    int oi = fdp.ConsumeIntegralInRange(0, nstrops - 1);
    std::string v = fdp.ConsumeRandomLengthString(128);
    curl_easy_setopt(easy, STR_OPTIONS[oi], v.c_str());
  }

  /* Hammer many long options with fuzzed values. */
  int nlongops = sizeof(LONG_OPTIONS) / sizeof(LONG_OPTIONS[0]);
  int nset_long = fdp.ConsumeIntegralInRange(1, 20);
  for(int i = 0; i < nset_long && fdp.remaining_bytes() > 4; i++) {
    int oi = fdp.ConsumeIntegralInRange(0, nlongops - 1);
    long v = fdp.ConsumeIntegral<int32_t>();
    curl_easy_setopt(easy, LONG_OPTIONS[oi], v);
  }

  /* slist options. libcurl does not take ownership of the slist; the caller
     must keep it alive until after the easy handle is cleaned up. */
  struct curl_slist *list = NULL;
  if(fdp.ConsumeBool()) {
    int n = fdp.ConsumeIntegralInRange(1, 4);
    for(int i = 0; i < n && fdp.remaining_bytes() > 1; i++) {
      std::string s = fdp.ConsumeRandomLengthString(128);
      list = curl_slist_append(list, s.c_str());
    }
    if(list)
      curl_easy_setopt(easy, CURLOPT_HTTPHEADER, list);
  }

  /* Duplicate, then free the duplicate — exercises the option-copy logic. */
  CURL *dup = curl_easy_duphandle(easy);
  curl_easy_cleanup(dup);

  /* Reset, exercising the reset path. */
  curl_easy_reset(easy);

  curl_easy_cleanup(easy);
  curl_slist_free_all(list);
  return 0;
}
