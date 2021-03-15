# edgegrid-rs
Akamai {OPEN} EdgeGrid Authentication for Rust

## Description
This library implements [Akamai {OPEN} EdgeGrid Authentication][1] for Rust.  
It is intended to augment any HTTP client library (Reqwest, Hyper, etc), so long as said library supports
custom headers.

## Overview
The library defines 1 struct and 2 macros to aid in the signing of HTTP API requests:

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

### Macros
Two macros are defined to sign requests: one for GETs, and one for POSTs.  Both must be called with, at minimum,
a reference to an instance of Authenticator, and a `&str` denoting the URI path+query to be called by the HTTP 
client of your choice.  The GET macro returns a single String with the signed AUTHENTICATION header, while the
POST macro returns a (String, String) tuple with the signed header and the POST body, as it may have been modified.

```rust
let uri = "/akamai/api/get/destination";
let signed_get_header = sign_get_request!(&signer, uri);
// Set the client AUTHENTICATION header to signed_get_header

let uri2 = "/akamai/api/post/destination";
let (signed_post_header, post_body) = sign_post_request(&signer, uri2);
// Set AUTH header etc
```

Additionally, the GET macro can take a `HashMap<String, String>` argument containing any HTTP headers that must 
be included in the signing process (See the Akamai API documentation for endpoints requiring extra headers).

```rust
let headers: HashMap<String, String> = my_client.get_headers();
let signed_get_header = sign_get_request!(&signer, uri, &headers);
```

Finally, the POST macro has 3 additional forms for specifying increasing amounts of data to be signed, 
including a `String` body, a `usize` max_body, and a `HashMap<String, String>` header map.

```rust
let signed_post_with_body = sign_post_request!(&signer, uri, &body);
let signed_post_with_max_body = sign_post_request!(&signer, uri, &body, maxsize);
let signed_post_with_everything = sign_post_request!(&signer, uri, &body, maxsize, &headers);
```

### Without Macros
If you don't feel like using the macros, you can still do things the old-fashioned way.  Create a mutable
instance of a `RequestData` struct using the builder model shown in the below example, then call the 
appropriate instance function on your `Authenticator`:

```rust
let mut request = RequestData::new(uri)            // only URI is required
                    .with_headers(header_hashmap)  // add optional headers to sign
                    .with_body(body_str)           // add optional body for POSTs
                    .with_max_body(max_usize);     // add optional max body size for POSTs

let signed_get_header = signer.get(request);
let (signed_post_header, post_body) = signer.post(request);
```

See the `examples` directory for a full example using Reqwest as the HTTP client.


[1]: https://developer.akamai.com/introduction/Client_Auth.html