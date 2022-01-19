#[macro_use] extern crate rocket;
extern crate serde;
extern crate rabe;
extern crate serde_json;

/* from https://github.com/Fraunhofer-AISEC/rabe/blob/master/console/src/mod.rs
    authgen        creates a new authority using attribute(s) or a policy.
    decrypt        decrypts a file using a key.
    delegate       delegates attributes to a new subkey (cp-schemes)
    encrypt        encrypts a file using attributes (kp-schemes) or a policy (cp-schemes).
    help           Prints this message or the help of the given subcommand(s)
    keygen         creates a user key sk using attributes (cp-schemes) or a policy (kp-schemes).
    req-attr-pk    Requests the attribute public key from an authority (BDABE).
    req-attr-sk    Requests the attribute public key from an authority (BDABE).
    setup          sets up a new scheme, creates the msk and pk or gp.
*/

use std::collections::HashMap;

use crate::rabe::{
    RabeError,
    schemes::{
        ac17,
        aw11,
        bdabe,
        bsw,
        lsw,
        mke08,
        yct14
    },
    utils::{
        policy::pest::PolicyLanguage,
    }
};

use rocket::http::Status;
use rocket::serde::json::{Json, Value, json};
use rocket::serde::{Serialize, Deserialize};

use rabe::schemes::ac17::{Ac17MasterKey, Ac17PublicKey};

#[derive(Debug, PartialEq, FromFormField)]
enum Scheme {
    AC17CP, AC17KP, AW11, BDABE, BSW, LSW, MKE08, YCT14
}

#[derive(Debug, PartialEq, FromFormField)]
enum Lang {
    Human, Json
}

#[get("/")]
fn index() -> &'static str {
    "Hello, rapini!"
}

#[derive(Responder)]
#[response(status = 200, content_type = "json")]
struct OkResponse(String);

#[get("/setup?<scheme>")]
fn setup(scheme: Vec<Scheme>) -> OkResponse {
    if scheme.len() == 0 {
        panic!("missing scheme parameter")
    }
    // TODO: make sure that only one scheme is passed here
    match scheme[0] {
        Scheme::AC17CP | Scheme::AC17KP => {
            let (pk, msk) = ac17::setup();
            return OkResponse(json!({"msk": msk, "pk": pk}).to_string() );
        },
        _ => {
            // this shouldn't happen
            panic!("unknown scheme in setup")
        }
    }
}

// TODO: use -> SetupResponse for setup()
#[derive(Deserialize, Debug)]
struct SetupResponse {
    pk: HashMap<String, Value>,
    msk: HashMap<String, Value>
}


#[serde(crate = "rocket::serde")]
#[derive(Deserialize, Serialize)]
struct EncryptBody<'r> {
    pk: &'r str,
    policy: Option<&'r str>,
    attributes: Option<&'r str>,
    plaintext: &'r str
}

fn parse_attribtes(attr_string: &str) -> Vec<String> {
    let mut attributes: Vec<String> = Vec::new();
    for at in attr_string.split_whitespace() {
        attributes.push(at.to_string());
    }
    attributes
}

#[post("/encrypt?<scheme>&<lang>", data = "<encrypt_body>")]
fn encrypt(scheme: Vec<Scheme>, lang: Vec<Lang>, encrypt_body: Json<EncryptBody<'_>>) -> OkResponse {    
    // TODO: make sure that only one scheme and kang is passed here
    let mut pl;
    match lang[0] {
        Lang::Json => {
            pl = PolicyLanguage::JsonPolicy
        },
        Lang::Human => {
            pl = PolicyLanguage::HumanPolicy
        }
    }
    let pk: Ac17PublicKey = serde_json::from_str(encrypt_body.pk).unwrap();
    let plaintext: Vec<u8> = serde_json::from_str(encrypt_body.plaintext).unwrap();
    
    let mut ct;
    match scheme[0] {
        
        Scheme::AC17CP => {
            let policy = serde_json::from_str(encrypt_body.policy.unwrap()).unwrap();
            let cp_ct = ac17::cp_encrypt(&pk, &policy, &plaintext, pl);

            ct = serde_json::to_string_pretty(&cp_ct).unwrap();
        },
        Scheme::AC17KP => {
            let attributes: Vec<String> = serde_json::from_str(encrypt_body.attributes.unwrap()).unwrap();
            let kp_ct = ac17::kp_encrypt(&pk, &attributes, &plaintext).unwrap();

            ct = serde_json::to_string_pretty(&kp_ct).unwrap();
        }
        _ => {
            // this shouldn't happen
            panic!("unknown scheme in encrypt")
        }
    }
    return OkResponse(json!({"ct": ct}).to_string());
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
    .mount("/", routes![setup])
    .mount("/", routes![encrypt])
}


#[cfg(test)]
mod test {
    use crate::{SetupResponse, EncryptBody};

    use super::rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    #[test]
    fn test_hello() {
        let client = Client::tracked(rocket()).unwrap();
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string(), Some("Hello, rapini!".into()));
    }

    fn get_setup_response(scheme: &str) -> SetupResponse {
        let client = Client::tracked(rocket()).unwrap();
        let response = client.get(format!("/setup?scheme={}", scheme)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response_string = &response.into_string().unwrap();
        // print!("response_string: {:?}", response_string);
        let setup_response: SetupResponse = serde_json::from_str(response_string).unwrap();
        // print!("setup_result: {:?}", setup_result);
        setup_response
    }

    #[test]
    fn test_ac17_setup() {
        let setup_response: SetupResponse = get_setup_response("AC17KP");
        assert!(setup_response.pk.len() > 0);
        assert!(setup_response.msk.len() > 0)
    }

    #[test]
    fn test_ac17_kp_encrypt() {
        let setup_response: SetupResponse = get_setup_response("AC17KP");
        assert!(setup_response.pk.len() > 0);
        assert!(setup_response.msk.len() > 0);

        let client = Client::tracked(rocket()).unwrap();

        let body = EncryptBody {
            pk: &serde_json::to_string(&setup_response.pk).unwrap(),
            attributes: Some("A B"),
            policy: None,
            plaintext: &"dance like no one's watching, encrypt like everyone is!"
        };

        let body_string = serde_json::to_string(&body).unwrap();

        let response = client.post("/encrypt?scheme=AC17KP&lang=Human")
            .body(&body_string)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}