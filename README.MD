# exist-JWT

[![Build Status](https://travis-ci.com/eXistSolutions/jwt.svg?token=qmpymKjbSAbb74pPJ4EC&branch=main)](https://travis-ci.com/eXistSolutions/jwt) ![JWT compatible](https://jwt.io/img/badge-compatible.svg)

eXist-db library to create and read [JSON Web Tokens](jwt.io) with arbitrary payloads.

Can be used to _authorise_ requests with restxq and controller.xql.

As long as you keep your secret you can trust the information in valid tokens. 

## Usage

exist-JWT is implemented as an XQuery module and packaged as an eXist-db xar package which will be installed alongside your app.

Install the [XAR](https://github.com/eXistSolutions/jwt/releases/) and

    import module namespace jwt="http://existsolutions.com/ns/jwt";

For more details look at [examples](https://github.com/eXistSolutions/jwt/tree/master/examples) and
[tests](https://github.com/eXistSolutions/jwt/tree/master/test).

## Requirements

- eXist-db version 4.7.0+
- eXist-db crypto lib

## Testing

### command line

Prequisites:

- node 10+
- `npm install`
- a running exist-db v4.7+ at localhost:8080 with jwt installed

`npm test`


### eXide

Prequisites:

- a running exist-db v4.7+ with jwt installed

Evaluate `/db/system/jwt-1.0.0/test/runner.xq`
