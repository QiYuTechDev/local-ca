use structopt::StructOpt;

use crate::gen::Gen;

#[derive(Debug, StructOpt)]
/// local-ca 本地证书库的管理
pub enum Cli {
    /// 生成新证书命令
    Gen(Gen),
}

impl Cli {
    pub fn run(&self) {
        match self {
            Cli::Gen(gen) => gen.run(),
        }
    }
}
