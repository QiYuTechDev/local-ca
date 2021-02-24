mod root;
mod server;
mod shared;
mod utils;

use structopt::StructOpt;

use root::GenRoot;
use server::GenServer;
use shared::GenMethod;

#[derive(Debug, StructOpt)]
/// 生成证书命令
pub enum Gen {
    /// 生成新的 根证书
    Root(GenRoot),
    /// 生成新的 服务器端证书
    Server(GenServer),
}

impl Gen {
    pub fn run(&self) {
        match self {
            Gen::Root(c) => c.run(),
            Gen::Server(s) => s.run(),
        }
    }
}
