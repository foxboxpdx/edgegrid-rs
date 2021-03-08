/*
 Original Author: FoxBoxPDX <foxboxpdx@gmail.com>

 License

   Copyright 2021 Melondog Software. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


extern crate openssl;
extern crate time;
extern crate uuid;

use openssl::sign::Signer;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::sha::Sha256;
use openssl::base64::encode_block;
use time::OffsetDateTime;
use uuid::Uuid;
use std::collections::HashMap;

/*
Akamai Edgegrid {OPEN} signing library

This library provides a struct and helper functions that add EdgeGrid
authentication support as specified at
https://developer.akamai.com/introduction/Client_Auth.html

It should work with any HTTP client library (Reqwest, Hyper, etc) that
allows headers to be specified.

See README.md for additional information
*/

// Reusable authenticator struct what with the functions that do the things
#[derive(Default)]
pub struct Authenticator {
    pub host: String,
    pub client_token: String,
    pub client_secret: String,
    pub access_token: String
}

impl Authenticator {
    /* 
        Private Static Methods
    */

    // Compute an HMAC digest using SHA256 and encode to base64
    fn base64_hmac_sha256(data: &str, keystr: &str) -> String {
        let key = PKey::hmac(keystr.as_bytes()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        let hmac = signer.sign_oneshot_to_vec(data.as_bytes()).unwrap();
        encode_block(&hmac).trim().to_string()
    }

    // Compute a SHA256 hash, encode to base64, trim any whitespace
    fn base64_sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let retval = hasher.finish();
        encode_block(&retval).trim().to_string()
    }

    // Normalize any headers to be used in the signature 
    // Convert header keys to lowercase, trim whitespace, and join everything
    // together into a tab-separated string
    fn normalize_headers(headers: &HashMap<String, String>) -> String {
        let mut retval = String::from("");
        let mut normed = Vec::new();
        for (key, value) in headers.iter() {
            normed.push(format!("{}:{}", key.to_ascii_lowercase(), value.trim()));
        }
        retval.push_str(&normed.join("\t"));
        retval
    }

    // If a request body is present, ensure it is no larger than [max_body] bytes long
    // and generate a base64'd sha256 hash of it
    fn process_body(body: &str, max: usize, method: &str) -> (String, String) {
        // Don't bother doing anything if this isn't a POST request or there's no body
        if method == "POST" && body.len() > 0 && max > 0 {
            // Truncate if needed
            if body.len() > max {
                body.to_string().truncate(max);
            }
            // Make hash and return
            let hash = Authenticator::base64_sha256(body);
            (hash, body.to_string())
        } else {
            ("".to_string(), "".to_string())
        }
    }

    /*
        Private Instance Methods
    */

    // Create a base64'd SHA256 HMAC digest signing key based on the secret and timestamp
    fn make_signing_key(&self, timestamp: &str) -> String {
        Authenticator::base64_hmac_sha256(timestamp, &self.client_secret)
    }

    // Create a tab-separated string with all data that will be used in signing
    fn make_data_to_sign(&self, request: &mut UnsignedRequest, method: &str) -> String {
        let (body_hash, trunc_body) = Authenticator::process_body(&request.body, request.max_body, method);
        // Replace the USRQ body with truncated body
        request.body = trunc_body;

        // Normalize the headers if any exist
        let normalized = Authenticator::normalize_headers(&request.headers);

        // Generate string
        let data_to_sign: Vec<&str> = vec![
            method,
            "https",
            &self.host,
            &request.request_uri,
            &normalized,
            &body_hash,
            &request.unsigned_header
        ];
        data_to_sign.join("\t")
    }

    // Build and sign the authorization header
    fn make_auth_header(&self, timestamp: &str, request: &mut UnsignedRequest, method: &str) -> String {
        // Generate the unsigned auth header by combining tokens, timestamp, and a nonce
        let auth_header = format!("EG1-HMAC-SHA256 client_token={};access_token={};timestamp={};nonce={};",
                            self.client_token,
                            self.access_token,
                            timestamp,
                            Uuid::new_v4()
                        );
        
        // Toss that into the UR struct so it can be passed around easier
        request.unsigned_header = auth_header.to_string();

        // Send everything off for signing and add the resulting base64 sha256 HMAC to the header string;
        // return the result
        format!("{}signature={}", auth_header, self.sign_request(request, method, timestamp))
    }

    fn sign_request(&self, request: &mut UnsignedRequest, method: &str, timestamp: &str) -> String {
        let data = self.make_data_to_sign(request, method);
        let key = self.make_signing_key(timestamp);
        Authenticator::base64_hmac_sha256(&data, &key)
    }

    /*
        Public Methods
    */

    // Create a new, reusable EdgeGrid Authenticator struct for a given API hostname
    // with the appropriate tokens and secrets
    pub fn new(h: &str, ct: &str, cs: &str, at: &str) -> Authenticator {
        Authenticator { 
            host: h.to_string(),
            client_token: ct.to_string(),
            client_secret: cs.to_string(),
            access_token: at.to_string()
        }
    }

    // Generate the Authorization header for a GET request
    pub fn get(&self, request: &mut UnsignedRequest) -> SignedRequest {
        // Generate a timestamp in the format Akamai demands
        let timestamp = OffsetDateTime::now_utc().format("%Y%m%dT%H:%M:%S+0000");

        // Do all the things
        let signed_header = self.make_auth_header(&timestamp, request, "GET");

        // Hand the result back
        SignedRequest::new(&signed_header)
    }

    // Generate the Authroization header for a POST request
    pub fn post(&self, request: &mut UnsignedRequest) -> SignedRequest {
        // Generate timestamp
        let timestamp = OffsetDateTime::now_utc().format("%Y%m%dT%H:%M:%S+0000");

        // Do all the things
        let signed_header = self.make_auth_header(&timestamp, request, "POST");

        // Hand back the result
        SignedRequest::new(&signed_header).with_body(&request.body)
    }
}

// Data required to generate the EdgeGrid authentication header for a particular api request
#[derive(Default)]
pub struct UnsignedRequest {
    pub request_uri: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub max_body: usize,
    pub unsigned_header: String
}

impl UnsignedRequest {
    // Since we have 4 possible variants for a user to create an UnsignedRequest, use the
    // builder pattern so they can set as many or as few as they want
    pub fn new(uri: &str) -> UnsignedRequest {
        UnsignedRequest {
            request_uri: uri.to_string(),
            ..Default::default()
        }
    }

    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = body.to_string();
        self
    }

    pub fn with_max_body(mut self, max: usize) -> Self {
        self.max_body = max;
        self
    }
}

// Authentication header and (if necessary) truncated request body
#[derive(Default)]
pub struct SignedRequest {
    pub auth_header: String,
    pub body: String
}

impl SignedRequest {
    // Builder pattern again in case we want to add more fields later
    pub fn new(header: &str) -> SignedRequest {
        SignedRequest {
            auth_header: header.to_string(),
            ..Default::default()
        }
    }

    pub fn with_body(mut self, body: &str) -> Self {
        self.body = body.to_string();
        self
    }
}
