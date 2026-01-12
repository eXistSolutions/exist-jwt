xquery version "3.1";

module namespace jwt = "http://existsolutions.com/ns/jwt";

import module namespace crypto ="http://expath.org/ns/crypto";


declare variable $jwt:epoch-start := xs:dateTime("1970-01-01T00:00:00Z");
declare variable $jwt:default-token-lifetime := 30*24*60*60; (:xs:dayTimeDuration("P30D");:)
declare variable $jwt:header := jwt:encode(map { "alg": "HS256", "typ": "JWT" });

(:~
 : Returns a map with two keys: "create" and "read".
 : Both are partially applied functions with an arity of one.
 : This is for comfort, having to pass only the payload to "create" and 
 : the token to "read".
 :
 : @param   $secret     a longer string which will be used to sign tokens
 : @param   $lifetime   the number of seconds each issued token stays valid
 : @returns map(xs:string, function(*))
 :)
declare function jwt:instance ($secret as xs:string, $lifetime as xs:integer) as map(*) {
    let $now := current-dateTime() => jwt:dateTime-to-epoch()

    return
        map {
            "create" : jwt:create(?, $now, $secret),
            "read" : jwt:read(?, $secret, $lifetime)
        }
};

(:~
 : Issue a signed JWT
 :
 : @param $payload any map(*) - the key "iat", for issued at, will be added
 : @param $time    seconds since $jwt:epoch-start, will be the value for "iat" 
 : @param $secret  the signing key
 : @return xs:string the signed token
 :)
declare function jwt:create ($payload as map(*), $time as xs:integer, $secret as xs:string) as xs:string {
    let $enc-payload :=
        $payload
            => map:put("iat", $time)
            => jwt:encode()

    return
        (
            $jwt:header,
            $enc-payload,
            jwt:sign($jwt:header || "." || $enc-payload, $secret)
        )
        => string-join(".")
};

(:~
 : Issue a signed JWT
 :
 : @param $token    a JWT to read and verify
 : @param $secret   the signing key
 : @param $lifetime how old, in seconds, the token is allowed to be
 : @return xs:string the signed token
 :)
declare function jwt:read ($token as xs:string, $secret as xs:string, $lifetime as xs:integer) as item()? {
    let $parts := tokenize($token, "\.")

    return
        if (count($parts) ne 3)
        then (error(xs:QName("invalid-token")))
        else if ($parts[1] ne $jwt:header)
        then (error(xs:QName("invalid-header")))
        else if (jwt:verify-signature($parts[2], $parts[3], $secret))
        then (
            (:  verify token lifetime (iat) :)
            let $payload := jwt:decode($parts[2])
            let $dt := jwt:dateTime-to-epoch(current-dateTime()) - $payload?iat
            return
                if ($dt > $lifetime)
                then (error(xs:QName("too-old"), $dt, jwt:epoch-to-dateTime($payload?iat)))
                else if ($dt < 0)
                then (error(xs:QName("future-date"), $dt, jwt:epoch-to-dateTime($payload?iat)))
                else ($payload)
        )    
        else (error(xs:QName("invalid-signature")))
};

declare function jwt:sign ($data as xs:string, $secret as xs:string) as xs:string {
    (:
     : This is a band-aid for the output of crypto:hmac being cast to a base64 encoded xs:string
     : which uses + and / characters. Since util:base64-encode-url-safe cannot operate on binary data,
     : we do a manual replacement here.
     :)
    crypto:hmac($data, $secret, "HMAC-SHA-256", "base64")
    => translate("+/=", "-_") 
};

(:~
 : verify signature
 :)
declare function jwt:verify-signature ($payload as xs:string, $signature as xs:string, $secret as xs:string) as xs:boolean {
    jwt:sign($jwt:header || "." || $payload, $secret) eq $signature
};

declare function jwt:read-header ($header-value as xs:string, $secret as xs:string, $lifetime as xs:integer) as item()? {
    substring-after($header-value, "Bearer ")
    => jwt:read($secret, $lifetime)
};

declare function jwt:dateTime-to-epoch($dateTime as xs:dateTime) as xs:integer {
    ($dateTime - $jwt:epoch-start) div xs:dayTimeDuration('PT1S')
};

declare function jwt:epoch-to-dateTime($ts as xs:integer) as xs:dateTime {
    $jwt:epoch-start + xs:dayTimeDuration(concat("PT", $ts, "S"))
};

(:~
 : encode an item() for use in the JWT
 : TODO: refactor to use arrow expressions again
 : after existdb issue is fixed.
 :)
declare
function jwt:encode ($data as item()) as xs:string {
    util:base64-encode-url-safe(
        serialize($data, map { "method": "json", "indent": false() }))
};

declare
function jwt:decode ($base64 as xs:string) as item()? {
    $base64
        => util:base64-decode()
        => parse-json()
};
