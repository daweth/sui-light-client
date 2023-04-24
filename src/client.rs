use std::{fmt::format, str::FromStr};

use async_trait::async_trait;
use serde_json::Value;

use hyper::{Client, Request, Body, Uri, client::HttpConnector, Method};
use hyper_tls::HttpsConnector;

use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::StructTag,
};
use sui_json_rpc_types::{
    SuiData, SuiMoveStruct, SuiMoveValue, SuiObjectData, SuiObjectDataOptions, SuiObjectResponse,
    SuiParsedData, SuiParsedMoveObject, SuiRawData,
};
use sui_transaction_builder::DataReader;
use sui_types::{
    base_types::{
        MoveObjectType, ObjectID, ObjectInfo, ObjectRef, ObjectType, SequenceNumber, SuiAddress,
        SUI_ADDRESS_LENGTH,
    },
    digests::{ObjectDigest, TransactionDigest},
    id::ID,
    object::Owner,
    TypeTag,
};

pub static DEFAULT_OPTIONS: SuiObjectDataOptions = SuiObjectDataOptions {
    show_type: true,
    show_owner: true,
    show_previous_transaction: true,
    show_display: false,
    show_content: true,
    show_bcs: false,
    show_storage_rebate: true,
};

pub struct SuiLightClient {
    http: Client<HttpsConnector<HttpConnector>>,
    uri: Uri,
}

impl SuiLightClient {
    pub fn init(u: String) -> Self {
        let url = u.as_str().parse::<Uri>().unwrap();

        let client = Client::builder().build::<_, Body>(HttpsConnector::new());

        Self {
            http: client,
            uri: url,
        }
    }

    pub fn http(&self) -> &Client<HttpsConnector<HttpConnector>> {
        &self.http
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }
}

#[async_trait]
impl DataReader for SuiLightClient {
    async fn get_owned_objects(
        &self,
        address: SuiAddress,
        object_type: StructTag,
    ) -> Result<Vec<ObjectInfo>, anyhow::Error> {
        let addr = format!("0x{}", short_str_lossless(address.to_inner()));

        let json_request_string = format!(
            r#"
           {{
               "jsonrpc": "2.0",
               "id": 1,
               "method": "suix_getOwnedObjects",
               "params": [{}]
           }}"#,
            addr
        );

        let json_value = serde_json::json!(json_request_string);


        let r = Request::builder()
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .uri(&self.uri)
            .body(Body::from(json_request_string))
//            .body(Body::empty())
            .expect("request builder");

        let res = self.http.request(r).await?;
        if res.status() != 200 {
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            panic!("The request failed! {:?}", body);
        }

        dbg!(res.body());

        Ok(parse_object_info_from_response(res.into_body()))
    }

    async fn get_object_with_options(
        &self,
        object_id: ObjectID,
        options: SuiObjectDataOptions,
    ) -> Result<SuiObjectResponse, anyhow::Error> {
        let json_request_string = format!(
            r#"{{ 
              "jsonrpc": "2.0", 
              "id": 1, 
              "method": "sui_getObject",
              "params": [ 
                {},
                {{ 
                  "showType": {},
                  "showOwner": {},
                  "showPreviousTransaction": {},
                  "showDisplay": {},
                  "showContent": {},
                  "showBcs": {},
                  "showStorageRebate": {} 
                }}
              ]
            }}"#,
            object_id.to_hex_uncompressed(),
            options.show_type,
            options.show_owner,
            options.show_previous_transaction,
            options.show_display,
            options.show_content,
            options.show_bcs,
            options.show_storage_rebate
        );

        let json_value = serde_json::json!(json_request_string);

        let r = Request::builder()
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .uri(&self.uri)
            .body(Body::from(json_request_string))
//            .body(Body::empty())
            .expect("request builder");

        let res = self.http.request(r).await?;
        if res.status() != 200 {
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            panic!("The request failed! {:?}", body);
        }

        dbg!(res.body());

        Ok(parse_object_from_response(res.into_body()))
    }

    async fn get_reference_gas_price(&self) -> Result<u64, anyhow::Error> {
        let json_request_string = format!(
            r#"
            {{
                "jsonrpc": "2.0",
                "id": 1,
                "method": "suix_getReferenceGasPrice"
            }}
            "#
        );

        let json_value = serde_json::json!(json_request_string);

        let r = Request::builder()
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .uri(&self.uri)
            .body(Body::from(json_request_string))
//            .body(Body::empty())
            .expect("request builder");

        let res = self.http.request(r).await?;
        if res.status() != 200 {
            let body = hyper::body::to_bytes(res.into_body()).await.unwrap();
            panic!("The request failed! {:?}", body);
        }

        dbg!(res.body());

        Ok(parse_gas_from_response(res.into_body()))
    }
}

fn simplify_options(o: SuiObjectDataOptions) -> [bool; 7] {
    [
        o.show_type,
        o.show_owner,
        o.show_previous_transaction,
        o.show_display,
        o.show_content,
        o.show_bcs,
        o.show_storage_rebate,
    ]
}

fn parse_object_from_response(input: Body) -> SuiObjectResponse {
    let fake_type_params = vec![TypeTag::Bool];

    let fake_struct_tag = StructTag {
        address: AccountAddress::TWO,
        module: Identifier::new("coin").unwrap(),
        name: Identifier::new("Coin").unwrap(),
        type_params: fake_type_params,
    };

    let fake_struct_fields = SuiMoveStruct::Runtime(vec![SuiMoveValue::Number(69)]);

    let fake_move_object = SuiParsedMoveObject {
        type_: fake_struct_tag,
        has_public_transfer: true,
        fields: fake_struct_fields,
    };

    let fake_object_content = SuiParsedData::MoveObject(fake_move_object);

    let fake_object_data = SuiObjectData {
        object_id: ObjectID::from_hex_literal(
            "0xbd4a8807df7b05c6f4569f3ef92c05ea38ea2e1eaac2455b7412fd8953f82fcd",
        )
        .unwrap(),
        version: SequenceNumber::from_u64(48138),
        digest: ObjectDigest::from_str("9nMCTJvv9ftWQCc1qVEpSzNAGtFunVDpGk2xiBjjhJHZ").unwrap(),
        type_: Some(ObjectType::Struct(
            sui_types::base_types::MoveObjectType::Coin(sui_types::TypeTag::Address),
        )),
        owner: Some(Owner::AddressOwner(
            SuiAddress::from_str(
                "0xfc8238ec72483cc0ca7dd86296f4cebaa15fc4f8207521b1710f7403db010a8f",
            )
            .unwrap(),
        )),
        previous_transaction: Some(
            TransactionDigest::from_str("CZUByEwbToqhZQ5FcnyYEWFoikZHvVSAdPPRcriFWM32").unwrap(),
        ),
        storage_rebate: Some(988000),
        display: None,
        content: Some(fake_object_content),
        bcs: None,
    };

    SuiObjectResponse {
        data: Some(fake_object_data),
        error: None,
    }
}

fn parse_object_info_from_response(input: Body) -> Vec<ObjectInfo> {

    let mut fake_type_tags = Vec::<TypeTag>::new();
    fake_type_tags.insert(0, TypeTag::Bool);

    let fake_struct_tag = StructTag {
        address: AccountAddress::from_hex_literal(
            "0xfc8238ec72483cc0ca7dd86296f4cebaa15fc4f8207521b1710f7403db010a8f",
        )
        .unwrap(),
        module: Identifier::new("fakeID").unwrap(),
        name: Identifier::new("fakeID").unwrap(),
        type_params: fake_type_tags,
    };

    let fake_object_info = ObjectInfo {
        object_id: ObjectID::from_hex_literal(
            "0x0013dadc29fcab80c84a30670e174851a3df95f4ae26ed8445a52fcc0267769a",
        )
        .unwrap(),
        version: SequenceNumber::from_u64(133863),
        digest: ObjectDigest::from_str("Dzh6YAyKFmZPhQNKKuZVtRfkWgFDyf73uuBiFBLAV9n2").unwrap(),
        type_: ObjectType::Struct(MoveObjectType::Other(fake_struct_tag)),
        owner: Owner::Immutable,
        previous_transaction: TransactionDigest::default(),
    };

    vec![fake_object_info]
}

fn parse_gas_from_response(input: Body) -> u64 {
    69
}

fn short_str_lossless(b: [u8; SUI_ADDRESS_LENGTH]) -> String {
    let hex_str = hex::encode(b).trim_start_matches('0').to_string();
    if hex_str.is_empty() {
        "0".to_string()
    } else {
        hex_str
    }
}
#[cfg(test)]
mod tests {
    use hyper::Uri;
    use sui_types::base_types::ObjectID;
    use sui_transaction_builder::DataReader;

    use crate::client::{SuiLightClient, DEFAULT_OPTIONS};

    async fn init() -> SuiLightClient{
        let rpc_url = String::from("https://sui-testnet-rpc.allthatnode.com");
        let client = SuiLightClient::init(rpc_url.clone());
        assert_eq!(client.uri().clone(), rpc_url.parse::<Uri>().unwrap());
        client
    }

    #[tokio::test]
    async fn test_get_reference_gas_price() {
        let client = init().await;

        let gas = client.get_reference_gas_price().await.unwrap();

        assert_eq!(gas, 69, "gas does not match");
    }

    #[tokio::test]
    async fn test_get_object_with_options() {
        let client = init().await;
        let object_id = ObjectID::from_hex_literal("0x018e1ba15a075b88a61c73d8f48313041422d5e8ce7bfed96f5eeb7ae11e7ef6").unwrap();

        let object = client.get_object_with_options(object_id, DEFAULT_OPTIONS.clone())
            .await 
            .unwrap();

        dbg!(object);
    }

}