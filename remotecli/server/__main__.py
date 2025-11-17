import os
import ssl
import uvicorn

def main():
    certfile = os.getenv("SSL_CERTFILE")
    keyfile = os.getenv("SSL_KEYFILE")
    allow_http = os.getenv("ALLOW_HTTP", "0") == "1"
    client_ca = os.getenv("SSL_CLIENT_CA")
    require_client = os.getenv("REQUIRE_CLIENT_CERT", "0") == "1"
    kwargs = {"host": "0.0.0.0", "port": 8000, "reload": False}
    if certfile and keyfile:
        kwargs.update({"ssl_certfile": certfile, "ssl_keyfile": keyfile})
        if client_ca and require_client:
            kwargs.update({"ssl_ca_certs": client_ca, "ssl_cert_reqs": ssl.CERT_REQUIRED})
    elif not allow_http:
        raise RuntimeError("TLS is required. Set SSL_CERTFILE and SSL_KEYFILE or ALLOW_HTTP=1 for non-production.")
    uvicorn.run("remotecli.server.app:app", **kwargs)

if __name__ == "__main__":
    main()