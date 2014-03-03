# Github Authentication Proxy

This is a reverse proxy using Github as an authentication scheme.

It's useful when you want to expose an internal web application but want some authentication.

## Usage

Firstly, you'll need to create a new github application.
Set the callback url to the location where the proxy will run, with the ```_callback``` prefix.
So if you're running on port 9999, and your site is ```example.org```, then the callback url will be ```http://example.org:9999/_callback```.

    # The port the proxy will run on.
    export PORT=9999
    # The application you're exposing.
    export TARGET_URI=http://localhost:9200
    # Users of this organisation will be able to see the application.
    export ORGANISATION=SoftwareDevelopersLimited
    # Github client ID.
    export CLIENT_ID=12121212
    # Github client secret.
    export CLIENT_SECRET=223134
    # Launch the proxy.
    go run server.go
