/*
Edgegrid-rs example: getlocations.rs

When supplied with proper credentials as environment variables, this program will
instantiate an Authenticator and UnsignedRequest to hit the edge server locations
API endpoint using a simple blocking Reqwest client.  Should work fine with an async client.

Expects the following environment variables:
CLIENT_TOKEN
CLIENT_SECRET
ACCESS_TOKEN
AKAMAI_API_HOST

*/

extern crate reqwest;
extern crate edgegrid_rs;

use edgegrid_rs::{Authenticator, UnsignedRequest};
use reqwest::header;
use std::env;

fn main() {
    // Pull in required env vars
    let ctoken = match env::var("CLIENT_TOKEN") {
        Ok(x) => x,
        Err(_) => panic!("Missing client token env var")
    };
    let csecret = match env::var("CLIENT_SECRET") {
        Ok(x) => x,
        Err(_) => panic!("Missing client secret env var")
    };
    let atoken = match env::var("ACCESS_TOKEN") {
        Ok(x) => x,
        Err(_) => panic!("Missing access token env var")
    };
    let apihost = match env::var("AKAMAI_API_HOST") {
        Ok(x) => x,
        Err(_) => panic!("Missing api host env var")
    };

    // Set the api URI we want to hit
    let uri = "/diagnostic-tools/v2/ghost-locations/available";

    // Prepare the Authenticator
    let authenticator = Authenticator::new(&apihost, &ctoken, &csecret, &atoken);

    // Prepare the client
    let client = match reqwest::blocking::Client::builder().build() {
        Ok(x) => x,
        Err(e) => { panic!("Error building client: {}", e); }
    };

    // Prepare the unsigned request - no body or headers needed
    let mut req = UnsignedRequest::new(uri);

    // Generate the signed auth header
    let signed = authenticator.get(&mut req);

    // Send the request and auth header to akamai
    let fullurl = format!("https://{}{}", apihost, uri);
    let result = client.get(&fullurl)
        .header(header::AUTHORIZATION, &signed.auth_header)
        .send();
    
    match result {
        Ok(x) => { println!("{}", x.text().unwrap()); },
        Err(e) => { panic!("Error sending api request: {}", e); }
    }
}