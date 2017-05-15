## DESCRIPTION

This tool detects XML Fast Infoset encoded HTTP requests in Burp based on the Content-Type header (xml/fastinfoset). Once the encoding is detected, it un-gzips the requests and decodes it to present a text-based readable user-friendly version.  After a request has been edited, the plugin converts it back to the original encoding, allowing requests to be modified on the fly.

![alt screenshot](https://image.ibb.co/jTZxmF/xmlfastinfoset.png)

Blog Post: <TO DO>

I used a decoding function from [Lu Jun](https://github.com/luj1985/albatross)'s code.

## USAGE

Download JAR file from dist directory and load it through Burp Extender module.
A new tab in Burp Proxy and Burp Repeater appears for any XML Fast Infoset encoded requests.
