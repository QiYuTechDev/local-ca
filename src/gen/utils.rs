use openssl::nid::Nid;
use openssl::x509;

/// 添加 x509 extension
pub fn gen_x509_ext(
    ctx: &x509::X509v3Context,
    nid: openssl::nid::Nid,
    value: &str,
) -> x509::X509Extension {
    x509::X509Extension::new_nid(None, Some(ctx), nid, value).unwrap()
}

/// 生成多个
pub fn gen_multi_x509_ext(
    ctx: &x509::X509v3Context,
    v: Vec<(Nid, &str)>,
) -> Vec<x509::X509Extension> {
    v.into_iter()
        .map(|(nid, value)| gen_x509_ext(ctx, nid, value))
        .collect()
}
