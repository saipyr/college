import os
import uvicorn

def main():
    certfile = os.getenv("SSL_CERTFILE")
    keyfile = os.getenv("SSL_KEYFILE")
    kwargs = {"host": "0.0.0.0", "port": 8000, "reload": False}
    if certfile and keyfile:
        kwargs.update({"ssl_certfile": certfile, "ssl_keyfile": keyfile})
    uvicorn.run("remotecli.server.app:app", **kwargs)

if __name__ == "__main__":
    main()