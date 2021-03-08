# edgegrid-rs
Akamai {OPEN} EdgeGrid Authentication for Rust

## Description
This library implements [Akamai {OPEN} EdgeGrid Authentication][1] for Rust.  
It is intended to augment any HTTP client library (Reqwest, Hyper, etc), so long as said library supports
custom headers.

## Overview
The library defines 3 structs to aid in the signing of HTTP API requests:

`Authenticator` is the primary struct and does the bulk of the heavy lifting.  Instantiate it with the API endpoint 
hostname and your client and access tokens and secrets to get a reusable signing factory of sorts.

```rust
let mut signer = Authenticator::new(
    "aka-xxxxxxx-xxxxxxx.luna.akamaiapis.net",
    "my_client_token_xyz",
    "my_client_secret_abc",
    "my_access_token_def"
);
```

`UnsignedRequest` describes an API request URI, along with additional optional data required to generate the Akamai 
authentication header.  A single `Authenticator` should be able to process any number of `UnsignedRequest` structs.
See the Akamai documentation for the specific API endpoints you are addressing for information about whether to include 
headers, a body, and/or a maximum body size when generating the authentication header.

```rust
let mut request = UnsignedRequest::new("/api/endpoint/uri");
    .with_headers(my_header_hashmap)  // Optional headers (see API documentation)
    .with_body(my_post_body)          // Optional body for POST operations
    .with_max_body(a_usize_integer);  // Optional maximum body size for POST operations
```

`SignedRequest` is the struct returned by the `Authenticator` after calculating all the fancy encryption whatnot for 
a given `UnsignedRequest`.  It contains the base64-encoded Authentication header and, if required, a (possibly truncated) 
copy of the request body.  Truncation occurs only if the body part of the `UnsignedRequest` exceeds the max_body parameter
supplied (no truncation occurs if no max_body paramater is supplied).

## Usage
It's as easy as 1-2-3!  1: Instantiate an `Authenticator` with your Akamai credentials.  2: Instantiate one or more
`UnsignedRequest`s that need auth headers.  3: Pass the requests into the appropriate function and receive a `SignedRequest`.

```rust
let mut signer = Authenticator::new(apihostname, clienttoken, clientsecret, accesstoken);
let mut getrequest = UnsignedRequest::new("/endpoint/v1/foo");
let mut postrequest = UnsignedRequest::new("/endpoint/v1/bar").with_body(postbody);

let signedgetreq = signer.get(&getrequest);
let signedpostreq = signer.post(&postrequest);
```

See the `examples` directory for a full example using Reqwest as the HTTP client.

### Important note
After calling `Authenticator`s get() or post() functions, be sure to use the resulting authentication header immediately,
as it is calculated with a timestamp and is time-sensitive.  Each authentication header may be used only once, but you can
generate as many `SignedRequest`s from an `UnsignedRequest` instance as you like; each will receive its own fresh timestamp
and internal UUID for signing.


[1]: https://developer.akamai.com/introduction/Client_Auth.html