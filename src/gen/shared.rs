use std::convert::Infallible;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
/// 生成方式
pub enum GenMethod {
    RSA,
    Ed25519,
}

impl FromStr for GenMethod {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rsa" => Ok(GenMethod::RSA),
            "ed25519" => Ok(GenMethod::Ed25519),
            _ => panic!("当前仅支持 RSA 和 ed25519 算法。"),
        }
    }
}
