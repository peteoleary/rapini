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


use crate::rabe::{
    schemes::{
        ac17,
    },
    utils::{
        policy::pest::PolicyLanguage,
    }
};

use rocket::http::Status;
use rocket::serde::json::{Json, json};
use rocket::serde::{Serialize, Deserialize};

use rabe::schemes::ac17::{Ac17PublicKey, Ac17MasterKey, Ac17KpCiphertext, Ac17KpSecretKey, Ac17CpCiphertext, Ac17CpSecretKey,
    kp_decrypt, kp_keygen, cp_decrypt, cp_keygen};

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
#[derive(Deserialize, Serialize)]
struct SetupResponse {
    pk: Ac17PublicKey,
    msk: Ac17MasterKey
}


#[derive(Deserialize, Serialize)]
struct EncryptBody {
    pk: Ac17PublicKey,
    policy: Option<String>,
    attributes: Option<String>,
    plain: Vec<u8>
}

fn parse_attributes(attr_string: &String) -> Vec<String> {
    let mut attributes: Vec<String> = Vec::new();
    for at in attr_string.split_whitespace() {
        attributes.push(at.to_string());
    }
    attributes
}

fn get_policy_language(lang: &Lang) -> PolicyLanguage {
    let pl;
    match lang {
        Lang::Json => {
            pl = PolicyLanguage::JsonPolicy
        },
        Lang::Human => {
            pl = PolicyLanguage::HumanPolicy
        }
    }
    pl
}

#[post("/encrypt?<scheme>&<lang>", data = "<encrypt_body>")]
fn encrypt(scheme: Vec<Scheme>, lang: Vec<Lang>, encrypt_body: Json<EncryptBody>) -> OkResponse {    
    // TODO: make sure that only one scheme and kang is passed here
    let pl = get_policy_language(&lang[0]);
    let plaintext: Vec<u8> = encrypt_body.plain.clone();
    
    let ct;
    match scheme[0] {
        
        Scheme::AC17CP => {
            let policy = encrypt_body.policy.as_ref().unwrap();
            let cp_ct = ac17::cp_encrypt(&encrypt_body.pk, &policy, &plaintext, pl);

            ct = json!(&cp_ct).to_string();
        },
        Scheme::AC17KP => {
            let attributes: Vec<String> = parse_attributes(&encrypt_body.attributes.as_ref().unwrap());
            let kp_ct = ac17::kp_encrypt(&encrypt_body.pk, &attributes, &plaintext).unwrap();

            ct = json!(&kp_ct).to_string();
        }
        _ => {
            // this shouldn't happen
            panic!("unknown scheme in encrypt")
        }
    }
    return OkResponse(ct);
}


#[derive(Deserialize, Serialize)]
struct KeyGenBody {
    msk: Ac17MasterKey,
    policy: Option<String>,
    attributes: Option<String>,
    cyphertext: Vec<u8>
}

#[post("/keygen?<scheme>&<lang>", data = "<keygen_body>")]
fn keygen(scheme: Vec<Scheme>, lang: Vec<Lang>, keygen_body: Json<KeyGenBody>) -> OkResponse {   
    let pl = get_policy_language(&lang[0]);
    let key: String;
    match scheme[0] {
        
        Scheme::AC17CP => {
            let sk: Ac17CpSecretKey = ac17::cp_keygen(&keygen_body.msk, &vec![]).unwrap();
            key = json!(sk).to_string();
        },
        Scheme::AC17KP => {
            let policy = keygen_body.policy.as_ref().unwrap();
            let sk: Ac17KpSecretKey = ac17::kp_keygen(&keygen_body.msk, &policy, pl).unwrap();
            key = json!(sk).to_string();
        }
        _ => {
            // this shouldn't happen
            panic!("unknown scheme in keygen")
        }
    }
    return OkResponse(key);
}

#[derive(Deserialize, Serialize)]
struct DecryptBody {
    sk: String,
    ct: String
}

#[post("/decrypt?<scheme>&<lang>", data = "<decrypt_body>")]
fn decrypt(scheme: Vec<Scheme>, lang: Vec<Lang>, decrypt_body: Json<DecryptBody>) -> OkResponse {   
    let pl = get_policy_language(&lang[0]);
    let mut plain: Vec<u8>;
    match scheme[0] {
        Scheme::AC17CP => {
            let sk: Ac17CpSecretKey = serde_json::from_str(&decrypt_body.sk).unwrap();
            let ct: Ac17CpCiphertext = serde_json::from_str(&decrypt_body.ct).unwrap();
            plain = cp_decrypt(&sk, &ct).unwrap()
        },
        Scheme::AC17KP => {
            let sk: Ac17KpSecretKey = serde_json::from_str(&decrypt_body.sk).unwrap();
            let ct: Ac17KpCiphertext = serde_json::from_str(&decrypt_body.ct).unwrap();
            plain = kp_decrypt(&sk, &ct).unwrap()
        }
        _ => {
            // this shouldn't happen
            panic!("unknown scheme in decrypt")
        }
    }
    return OkResponse(json!({"plain": plain}).to_string() );
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
    .mount("/", routes![setup])
    .mount("/", routes![encrypt])
    .mount("/", routes![decrypt])
    .mount("/", routes![keygen])
}


#[cfg(test)]
mod test {
    use crate::{SetupResponse, EncryptBody, parse_attributes};

    use std::env;

    use super::rocket;
    use rabe::schemes::ac17::{Ac17PublicKey, Ac17MasterKey, Ac17KpCiphertext, Ac17KpSecretKey, kp_decrypt, kp_keygen, cp_decrypt, cp_keygen};
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    use crate::rabe::{
        schemes::{
            ac17,
        },
        utils::{
            policy::pest::PolicyLanguage,
        }
    };

    fn get_rocket_client() -> Client {
        // TODO: see if we can point this client to a remote address to run test suite against server
        Client::tracked(rocket()).unwrap()
    }

    #[test]
    fn test_hello() {
        let client = get_rocket_client();
        let response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string(), Some("Hello, rapini!".into()));
    }

    fn get_setup_response(scheme: &str) -> SetupResponse {
        let client = get_rocket_client();
        let response = client.get(format!("/setup?scheme={}", scheme)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response_string = &response.into_string().unwrap();
        // print!("response_string: {:?}", response_string);
        let setup_response: SetupResponse = serde_json::from_str(response_string).unwrap();
        // print!("setup_result: {:?}", setup_result);
        setup_response
    }

    fn is_valid_master_key(_mk: Ac17MasterKey) -> bool {
        true
    }

    static PLAINTEXT_SAMPLE: &str = "dance like no one's watching, encrypt like everyone is!";

    #[test]
    fn test_ac17_setup() {
        let setup_response: SetupResponse = get_setup_response("AC17KP");
        assert!(is_valid_master_key(setup_response.msk));
    }

    fn get_encrypt_body(plain: Vec<u8>, pk: Ac17PublicKey) -> EncryptBody {

        let body = EncryptBody {
            pk: pk,
            attributes: Some("A B".to_string()),
            policy: None,
            plain: plain
        };
        body
    }

    #[test]
    fn test_encrypt_body_serialization() {
        let setup_response: SetupResponse = get_setup_response("AC17KP");

        let body_string = serde_json::to_string(&get_encrypt_body(PLAINTEXT_SAMPLE.to_string().into_bytes(), setup_response.pk)).unwrap();

        let _new_body: EncryptBody = serde_json::from_str(&body_string).unwrap();

        assert!(true)
    }

    fn do_test_kp_encrypt(plain: Vec<u8>) {
        let setup_response: SetupResponse = get_setup_response("AC17KP");

        let client = get_rocket_client();

        let body = get_encrypt_body(plain.clone(), setup_response.pk);

        let body_string = serde_json::to_string(&body).unwrap();

        let response = client.post("/encrypt?scheme=AC17KP&lang=Human")
            .body(&body_string)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let response_string = &response.into_string().unwrap();
    
        let ct: Ac17KpCiphertext = serde_json::from_str(response_string).unwrap();
        // let kpencrypt_response: Ac17KpCiphertext = serde_json::from_str(response_string).unwrap();

        let sk: Ac17KpSecretKey = kp_keygen(&setup_response.msk, &String::from(r#""A" and "B""#), PolicyLanguage::HumanPolicy).unwrap();

        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plain);
    }

    #[test]
    fn test_ac17_kp_encrypt() {
        do_test_kp_encrypt(PLAINTEXT_SAMPLE.to_string().into_bytes());
    }

    #[test]
    fn test_ac17_kp_encrypt_small_image() {
        do_test_kp_encrypt(image::open("src/pixel_1.jpeg").unwrap().into_bytes());
    }

    #[test]
    fn test_attribute_parse() {
        let attributes: Vec<String> = parse_attributes(&"A B".to_string());
        assert!(attributes[0].eq("A"));
        assert!(attributes[1].eq("B"));
    }

    #[test]
    fn test_ac17_kp_decrypt() {
    }
}