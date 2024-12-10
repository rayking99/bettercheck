# Security Report: requests

Generated: 20241211_064551

## Summary

- Total Dependencies: 5
- Total Vulnerabilities: 41

## requests (Depth: 0)

### Vulnerabilities (11)

- **GHSA-652x-xj99-gmcc** (OSV)
  - Requests (aka python-requests) before 2.3.0 allows remote servers to obtain sensitive information by reading the Proxy-Authorization header in a redirected request....

- **GHSA-9wx4-h78v-vm56** (OSV)
  - When making requests through a Requests `Session`, if the first request is made with `verify=False` to disable cert verification, all subsequent requests to the same origin will continue to ignore cer...

- **GHSA-cfj3-7x9c-4p3h** (OSV)
  - Requests (aka python-requests) before 2.3.0 allows remote servers to obtain a netrc password by reading the Authorization header in a redirected request....

- **GHSA-j8r2-6x86-q33q** (OSV)
  - ### Impact

Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` headers to destination servers, specifically during redirects to an HTTPS origin. This is a...

- **GHSA-pg2w-x9wp-vw92** (OSV)
  - The `resolve_redirects` function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect....

- **GHSA-x84v-xcm2-53pg** (OSV)
  - The Requests package through 2.19.1 before 2018-09-14 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remo...

- **PYSEC-2014-13** (OSV)
  - Requests (aka python-requests) before 2.3.0 allows remote servers to obtain a netrc password by reading the Authorization header in a redirected request....

- **PYSEC-2014-14** (OSV)
  - Requests (aka python-requests) before 2.3.0 allows remote servers to obtain sensitive information by reading the Proxy-Authorization header in a redirected request....

- **PYSEC-2015-17** (OSV)
  - The resolve_redirects function in sessions.py in requests 2.1.0 through 2.5.3 allows remote attackers to conduct session fixation attacks via a cookie without a host value in a redirect....

- **PYSEC-2018-28** (OSV)
  - The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to dis...

- **PYSEC-2023-74** (OSV)
  - Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint. This is a product of how we use `re...

## charset-normalizer (Depth: 1)

No known vulnerabilities

## idna (Depth: 1)

### Vulnerabilities (2)

- **GHSA-jjg7-2v4v-x38h** (OSV)
  - ### Impact
A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service.

### Patches
The function has been refined to reject ...

- **PYSEC-2024-60** (OSV)
  - A vulnerability was identified in the kjd/idna library, specifically within the `idna.encode()` function, affecting version 3.6. The issue arises from the function's handling of crafted input strings,...

## urllib3 (Depth: 1)

### Vulnerabilities (23)

- **GHSA-34jh-p97f-mpxf** (OSV)
  - When using urllib3's proxy support with `ProxyManager`, the `Proxy-Authorization` header is only sent to the configured proxy, as expected.

However, when sending HTTP requests *without* using urllib3...

- **GHSA-5phf-pp7p-vc2r** (OSV)
  - ### Impact

Users who are using an HTTPS proxy to issue HTTPS requests and haven't configured their own SSLContext via `proxy_config`.
Only the default SSLContext is impacted.

### Patches

[urllib3 >...

- **GHSA-g4mx-q9vg-27p4** (OSV)
  - urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 303 "See Other" after the request had its method changed from one that could accept a request body ...

- **GHSA-gwvm-45gx-3cf8** (OSV)
  - urllib3 before 1.24.2 does not remove the authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credentials in t...

- **GHSA-hmv2-79q8-fv6g** (OSV)
  - The _encode_invalid_chars function in util/url.py in the urllib3 library 1.25.2 through 1.25.7 for Python allows a denial of service (CPU consumption) because of an inefficient algorithm. The percent_...

- **GHSA-mh33-7rrq-662w** (OSV)
  - The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates, which results in SSL connections succe...

- **GHSA-q2q7-5pp4-w6pg** (OSV)
  - ### Impact

When provided with a URL containing many `@` characters in the authority component the authority regular expression exhibits catastrophic backtracking causing a denial of service if a URL ...

- **GHSA-r64q-w8jr-g9qp** (OSV)
  - In the urllib3 library through 1.24.2 for Python, CRLF injection is possible if the attacker controls the request parameter....

- **GHSA-v4w5-p2hg-8fh6** (OSV)
  - Versions 1.17 and 1.18 of the Python urllib3 library suffer from a vulnerability that can cause them, in certain configurations, to not correctly validate TLS certificates. This places users of the li...

- **GHSA-v845-jxx5-vc9f** (OSV)
  - urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user. However, it is possible for a user to specify a `C...

- **GHSA-wqvq-5m8c-6g24** (OSV)
  - urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of `putrequest()`. NOTE: t...

- **GHSA-www2-v7xj-xrc6** (OSV)
  - urllib3 before version 1.23 does not remove the Authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credential...

- **PYSEC-2017-98** (OSV)
  - Versions 1.17 and 1.18 of the Python urllib3 library suffer from a vulnerability that can cause them, in certain configurations, to not correctly validate TLS certificates. This places users of the li...

- **PYSEC-2018-32** (OSV)
  - urllib3 before version 1.23 does not remove the Authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credential...

- **PYSEC-2019-132** (OSV)
  - In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the request parameter....

- **PYSEC-2019-133** (OSV)
  - The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA certificates is different from the OS store of CA certificates, which results in SSL connections succe...

- **PYSEC-2020-148** (OSV)
  - urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of putrequest(). NOTE: thi...

- **PYSEC-2020-149** (OSV)
  - The _encode_invalid_chars function in util/url.py in the urllib3 library 1.25.2 through 1.25.7 for Python allows a denial of service (CPU consumption) because of an inefficient algorithm. The percent_...

- **PYSEC-2021-108** (OSV)
  - An issue was discovered in urllib3 before 1.26.5. When provided with a URL containing many @ characters in the authority component, the authority regular expression exhibits catastrophic backtracking,...

- **PYSEC-2021-59** (OSV)
  - The urllib3 library 1.26.x before 1.26.4 for Python omits SSL certificate validation in some cases involving HTTPS to HTTPS proxies. The initial connection to the HTTPS proxy (if an SSLContext isn't g...

- **PYSEC-2023-192** (OSV)
  - urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header special or provide any helpers for managing cookies over HTTP, that is the responsibility of t...

- **PYSEC-2023-207** (OSV)
  - urllib3 before 1.24.2 does not remove the authorization HTTP header when following a cross-origin redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credentials in t...

- **PYSEC-2023-212** (OSV)
  - urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 after the request had i...

## certifi (Depth: 1)

### Vulnerabilities (5)

- **GHSA-248v-346w-9cwc** (OSV)
  - Certifi 2024.07.04 removes root certificates from "GLOBALTRUST" from the root store. These are in the process of being removed from Mozilla's trust store.

GLOBALTRUST's root certificates are being re...

- **GHSA-43fp-rhv2-5gv8** (OSV)
  - Certifi 2022.12.07 removes root certificates from "TrustCor" from the root store. These are in the process of being removed from Mozilla's trust store.

TrustCor's root certificates are being removed ...

- **GHSA-xqr8-7jwr-rhp7** (OSV)
  - Certifi 2023.07.22 removes root certificates from "e-Tugra" from the root store. These are in the process of being removed from Mozilla's trust store.

 e-Tugra's root certificates are being removed p...

- **PYSEC-2022-42986** (OSV)
  - Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi 2022.12.07 removes root certificates from...

- **PYSEC-2023-135** (OSV)
  - Certifi 2023.07.22 removes root certificates from "e-Tugra" from the root store. These are in the process of being removed from Mozilla's trust store. e-Tugra's root certificates are being removed pur...
