mod root;

use structopt::StructOpt;

use root::GenRoot;

#[derive(Debug, StructOpt)]
/// 生成证书命令
pub enum Gen {
    /// 生成新的 根证书
    Root(GenRoot),
}

impl Gen {
    pub fn run(&self) {
        match self {
            Gen::Root(c) => c.run(),
        }
    }
}
