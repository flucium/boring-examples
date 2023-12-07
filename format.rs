pub mod base64{
  pub fn encode(input:&[u8]) -> String{
    boring::base64::encode_block(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
  }

  pub fn decode(string:&str) -> Result<Vec<u8>,()>{
    boring::base64::decode_block(&b64).map_err(|_|())
  }
}

pub mod pem{
}
