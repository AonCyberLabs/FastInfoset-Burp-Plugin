DESCRIPTION
=========== 
This tool detects XML Fast Infoset encoding HTTP requests in Burp based on Content-Type header (xml/fastinfoset). Once the encoding is detected, it un-gzip the requests and 
decodes it to presents a text-based readable user-friendly version.  After tampering the requests it converts the request back to the original encoding, so it allows to modify requests on the fly.

![alt screenshot](https://image.ibb.co/jTZxmF/xmlfastinfoset.png)

Blog Post: <TO DO>

USAGE
======

Download JAR file from dist directory and load it through Burp Extender module.
A new tab in Burp Proxy and Burp Repeater appears for any XML Fast Infoset encoded requests.
