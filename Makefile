
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


view-root:
	$(openssl) x509 -noout -text -in data/cert.pem
