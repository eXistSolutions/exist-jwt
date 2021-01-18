# exist-JWT

![Semantic Release](https://github.com/eXistSolutions/exist-jwt/workflows/Semantic%20Release/badge.svg) [![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release) ![JWT compatible](https://jwt.io/img/badge-compatible.svg)

eXist-db library to create and read [JSON Web Tokens](jwt.io) with arbitrary payloads.

Can be used to _authorise_ requests with restxq and controller.xql.

As long as you keep your secret you can trust the information in valid tokens. 

## Usage

exist-JWT is implemented as an XQuery module and packaged as an eXist-db xar package which will be installed alongside your app.

Install the [XAR](https://github.com/eXistSolutions/jwt/releases/) and

    import module namespace jwt="http://existsolutions.com/ns/jwt";

For more details look at [examples](https://github.com/eXistSolutions/jwt/tree/master/src/examples) and
[tests](https://github.com/eXistSolutions/jwt/tree/master/src/test).

## Requirements

- eXist-db version 5.0.0+
- eXist-db crypto lib 1.0.0+

## Testing

### Command line

Prequisites:

- node 10+
- a running exist-db at localhost:8080

Clone this repository and

1. Install dev dependencies
    - `npm install`
2. Build and install the XAR package in your exist-db instance
    - `npm start`
3. Run the testsuite
    - `npm test`

### eXide

Prequisites:

- a running exist-db with jwt installed

Evaluate `test/runner.xq`

### Getting and using a token

This interaction diagram shows how a token is created and used
to access a restricted resource.

![](src/doc/interaction_diagram.png?raw=true)