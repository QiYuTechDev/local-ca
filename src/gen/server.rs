use openssl::nid::Nid;
use structopt::StructOpt;

use super::{utils, GenMethod};
use openssl::x509::X509Builder;

#[derive(Debug, StructOpt)]
/// 生成新的根证书
pub struct GenServer {
    /// 根证书路径
    #[structopt(long)]
    root_cert: String,
    /// 根证书私钥
    #[structopt(long)]
    root_key: String,
    /// 证书保存的文件
    #[structopt(long)]
    cert_file: String,
    /// 公钥保存的路径
    #[structopt(long)]
    public_key_file: String,
    /// 密钥保存的路径
    #[structopt(long)]
    private_key_file: String,
    #[structopt(long)]
    /// 证书申请文件路径
    req_file: String,
    /// 生成方式
    #[structopt(long)]
    method: GenMethod,
}

impl GenServer {
    /// 生成新的服务器端证书
    pub fn run(&self) {
        match self.method {
            GenMethod::RSA => self.gen_rsa_server_cert(),
            GenMethod::Ed25519 => self.gen_ed25519_server_cert(),
        }
    }

    fn gen_rsa_server_cert(&self) {
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

        {
            let public = pkey.public_key_to_pem().unwrap();
            let p = String::from_utf8(public).unwrap();
            std::fs::write(self.public_key_file.as_str(), p).unwrap();
        }
        {
            let private = pkey.private_key_to_pem_pkcs8().unwrap();
            let p = String::from_utf8(private).unwrap();
            std::fs::write(self.private_key_file.as_str(), p).unwrap();
        }

        let mut builder = openssl::x509::X509Req::builder().unwrap();

        builder.set_version(2).unwrap();
        builder.set_pubkey(pkey.as_ref()).unwrap();
        let subject_name = {
            let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
            x509_name.append_entry_by_text("C", "CN").unwrap();
            x509_name.append_entry_by_text("ST", "BJ").unwrap();
            x509_name.append_entry_by_text("O", "QiYuTech").unwrap();
            x509_name.append_entry_by_text("CN", "server").unwrap();
            x509_name.build()
        };
        builder.set_subject_name(subject_name.as_ref()).unwrap();

        let es = {
            let ctx = builder.x509v3_context(None);
            utils::gen_multi_x509_ext(
                &ctx,
                vec![
                    (Nid::BASIC_CONSTRAINTS, "critical,CA:FALSE"),
                    (
                        Nid::KEY_USAGE,
                        "critical, digitalSignature, keyEncipherment",
                    ),
                    (Nid::EXT_KEY_USAGE, "serverAuth"),
                    (Nid::SUBJECT_KEY_IDENTIFIER, "hash"),
                    // (Nid::AUTHORITY_KEY_IDENTIFIER, "keyid,issuer:always"),
                    // thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value:
                    // ErrorStack([Error { code: 570912889, library: "X509 V3 routines",
                    // function: "v2i_AUTHORITY_KEYID", reason: "no issuer certificate",
                    // file: "crypto/x509v3/v3_akey.c", line: 104 }])', src/gen/utils.rs:10:63
                    (Nid::NETSCAPE_CERT_TYPE, "server"),
                    (Nid::NETSCAPE_COMMENT, "QiYuTech Server Cert"),
                    (
                        Nid::SUBJECT_ALT_NAME,
                        "DNS:www.qiyutech.tech, DNS:user.qiyutech.tech",
                    ),
                ],
            )
        };

        {
            let mut stack = openssl::stack::Stack::new().unwrap();
            for e in es {
                stack.push(e).unwrap();
            }
            builder.add_extensions(stack.as_ref()).unwrap();
        }

        builder
            .sign(pkey.as_ref(), openssl::hash::MessageDigest::sha256())
            .unwrap();

        let req = builder.build();

        let pem = req.to_pem().unwrap();
        let cert_req = String::from_utf8(pem).unwrap();
        std::fs::write(self.req_file.as_str(), cert_req).unwrap();

        let mut x509 = X509Builder::new().unwrap();

        let sn = {
            let bn = {
                let mut bn = openssl::bn::BigNum::new().unwrap();
                bn.clear();
                bn.add_word(2).unwrap(); // todo fix this
                bn
            };
            openssl::asn1::Asn1Integer::from_bn(bn.as_ref()).unwrap()
        };
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(10 * 365).unwrap();

        let root = std::fs::read(self.root_key.as_str()).unwrap();

        let private = openssl::pkey::PKey::private_key_from_pem(root.as_slice()).unwrap();


        {
            let es = req.extensions().unwrap();

            for e in es {
                x509.append_extension(e).unwrap();
            }
        }
        x509.set_subject_name(req.subject_name()).unwrap();
        x509.set_version(req.version()).unwrap();
        x509.set_serial_number(&sn).unwrap();
        x509.set_not_before(not_before.as_ref()).unwrap();
        x509.set_not_after(not_after.as_ref()).unwrap();
        x509.set_pubkey(req.public_key().unwrap().as_ref()).unwrap();
        x509.sign(&private, openssl::hash::MessageDigest::sha256()).unwrap();
        let d = x509.build();
        let out = d.to_pem().unwrap();
        std::fs::write(self.cert_file.as_str(), out.as_slice()).unwrap();
    }

    fn gen_ed25519_server_cert(&self) {}
}
