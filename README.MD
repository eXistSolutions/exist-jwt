# exist-JWT

[![Build Status](https://travis-ci.com/eXistSolutions/jwt.svg)](https://travis-ci.com/eXistSolutions/jwt) ![JWT compatible](https://jwt.io/img/badge-compatible.svg)

existdb library to create and read [JSON Web Tokens](jwt.io) with arbitrary payloads.

Can be used to _authorise_ requests with restxq and controller.xql.

As long as you keep your secret you can trust the information in valid tokens. 

## Usage

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
- exist-db v4.7+ at localhost:8080 with jwt XAR installed

`npm test`


### eXide

Prequisites:

- exist-db v4.7+ with jwt XAR installed

Evaluate `/db/system/jwt-1.0.0/tests/runner.xq`
