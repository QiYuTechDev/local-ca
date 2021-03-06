use openssl::nid::Nid;
use structopt::StructOpt;

use super::utils;
use super::GenMethod;

#[derive(Debug, StructOpt)]
/// 生成新的根证书
pub struct GenRoot {
    /// 证书保存的文件
    #[structopt(long)]
    cert_file: String,
    /// 公钥保存的路径
    #[structopt(long)]
    public_key_file: String,
    /// 密钥保存的路径
    #[structopt(long)]
    private_key_file: String,
    /// 生成方式
    #[structopt(long)]
    method: GenMethod,
}

impl GenRoot {
    /// 生成新的根证书
    pub fn run(&self) {
        match self.method {
            GenMethod::Ed25519 => self.gen_es25519_root(),
            GenMethod::RSA => self.gen_rsa_root(),
        }
    }

    /// 生成 RSA 根证书
    fn gen_rsa_root(&self) {
        let rsa = openssl::rsa::Rsa::generate(4096).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        self.gen_and_write_to_file(pkey, true)
    }

    /// 生成 ED25519 根证书
    fn gen_es25519_root(&self) {
        let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();

        self.gen_and_write_to_file(pkey, false)
    }

    fn gen_and_write_to_file(
        &self,
        pkey: openssl::pkey::PKey<openssl::pkey::Private>,
        use_hash: bool,
    ) {
        let pub_key = {
            let pub_key = pkey.public_key_to_pem().unwrap();
            String::from_utf8(pub_key).unwrap()
        };
        std::fs::write(self.public_key_file.as_str(), pub_key).unwrap();

        let pri_key = {
            let pri_key = pkey.private_key_to_pem_pkcs8().unwrap();
            String::from_utf8(pri_key).unwrap()
        };
        std::fs::write(self.private_key_file.as_str(), pri_key).unwrap();

        let sn = {
            let bn = {
                let mut bn = openssl::bn::BigNum::new().unwrap();
                bn.clear();
                bn.add_word(1).unwrap(); // todo fix this
                bn
            };
            openssl::asn1::Asn1Integer::from_bn(bn.as_ref()).unwrap()
        };
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(10 * 365).unwrap();

        let subject_name = {
            let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
            x509_name.append_entry_by_text("C", "CN").unwrap();
            x509_name.append_entry_by_text("ST", "BJ").unwrap();
            x509_name.append_entry_by_text("O", "QiYuTech").unwrap();
            x509_name.append_entry_by_text("CN", "root").unwrap();
            x509_name.build()
        };
        let issuer_name = {
            let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
            x509_name.append_entry_by_text("C", "CN").unwrap();
            x509_name.append_entry_by_text("ST", "BJ").unwrap();
            x509_name.append_entry_by_text("O", "QiYuTech").unwrap();
            x509_name.append_entry_by_text("CN", "root").unwrap();
            x509_name.build()
        };


        let x509 = {
            let mut c = openssl::x509::X509Builder::new().unwrap();
            let es = {
                let ctx = c.x509v3_context(None, None);
                utils::gen_multi_x509_ext(
                    &ctx,
                    vec![
                        (Nid::BASIC_CONSTRAINTS, "critical,CA:TRUE"),
                        (Nid::KEY_USAGE, "critical,keyCertSign,cRLSign"),
                        (Nid::SUBJECT_KEY_IDENTIFIER, "hash"),
                        (Nid::NETSCAPE_CERT_TYPE, "sslCA"),
                        (Nid::NETSCAPE_COMMENT, "QiYuTech Self-Sign CA"),
                    ],
                )
            };

            for e in es {
                c.append_extension(e).unwrap();
            }
            c.set_subject_name(subject_name.as_ref()).unwrap();
            c.set_issuer_name(issuer_name.as_ref()).unwrap();
            c.set_version(2).unwrap();
            c.set_serial_number(sn.as_ref()).unwrap();
            c.set_not_before(not_before.as_ref()).unwrap();
            c.set_not_after(not_after.as_ref()).unwrap();
            c.set_pubkey(pkey.as_ref()).unwrap();
            if use_hash {
                c.sign(pkey.as_ref(), openssl::hash::MessageDigest::sha256())
                    .unwrap();
            } else {
                // use_hash is https://github.com/sfackler/rust-openssl/issues/1197
                c.sign(pkey.as_ref(), unsafe {
                    openssl::hash::MessageDigest::from_ptr(std::ptr::null())
                })
                    .unwrap();
            }
            c.build()
        };

        let cert = {
            let cert = x509.to_pem().unwrap();
            String::from_utf8(cert).unwrap()
        };

        std::fs::write(self.cert_file.as_str(), cert).unwrap();
    }
}
