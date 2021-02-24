
openssl=/usr/local/Cellar/openssl@1.1/1.1.1j/bin/openssl

gen-root-rsa:
	cargo run -- gen root                   \
	    --cert-file        data/cert.pem    \
	    --private-key-file data/private.pem \
	    --public-key-file  data/public.pem  \
	    --method rsa

gen-root-ed25519:
	cargo run -- gen root                   \
	    --cert-file        data/cert.pem    \
	    --private-key-file data/private.pem \
	    --public-key-file  data/public.pem  \
	    --method ed25519

gen-server-rsa:
	cargo run -- gen server                 \
	    --root-cert        data/cert.pem    \
	    --root-key         data/private.pem \
	    --cert-file        data/server_cert.pem    \
	    --public-key-file  data/server_public.pem  \
	    --private-key-file data/server_private.pem \
	    --req-file         data/server_req.pem     \
	    --method rsa

view-server-req:
	$(openssl) req -in data/server_req.pem -noout -text

view-root-certificate:
	$(openssl) x509 -noout -text -in data/cert.pem

view-server-certificate:
	$(openssl) x509 -noout -text -in data/server_cert.pem
