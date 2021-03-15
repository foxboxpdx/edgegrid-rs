/*
Edgegrid-rs example: getlocations.rs

When supplied with proper credentials as environment variables, this program will
instantiate an Authenticator and UnsignedRequest to hit the edge server locations
API endpoint using a simple blocking Reqwest client.  Should work fine with an async client.

Expects the following environment variables:
client_token
client_secret
access_token
host (the akamai api endpoint hostname for the given account credentials)

*/

extern crate reqwest;
#[macro_use] extern crate edgegrid_rs;

use edgegrid_rs::Authenticator;
use reqwest::header;
use std::env;

fn main() {
    // Pull in required env vars
    let ctoken = match env::var("client_token") {
        Ok(x) => x,
        Err(_) => panic!("Missing client token env var")
    };
    let csecret = match env::var("client_secret") {
        Ok(x) => x,
        Err(_) => panic!("Missing client secret env var")
    };
    let atoken = match env::var("access_token") {
        Ok(x) => x,
        Err(_) => panic!("Missing access token env var")
    };
    let apihost = match env::var("host") {
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

    // Generate the signed auth header
    let signed = sign_get_request!(&authenticator, &uri);

    // Send the request and auth header to akamai
    let fullurl = format!("https://{}{}", apihost, uri);
    let result = client.get(&fullurl)
        .header(header::AUTHORIZATION, &signed)
        .send();
    
    match result {
        Ok(x) => { println!("{}", x.text().unwrap()); },
        Err(e) => { panic!("Error sending api request: {}", e); }
    }
}