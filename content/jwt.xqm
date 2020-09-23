xquery version "3.1";

module namespace jwt = "http://existsolutions.com/ns/jwt";


import module namespace crypto ="http://expath.org/ns/crypto";


declare variable $jwt:epoch-start := xs:dateTime("1970-01-01T00:00:00Z");
declare variable $jwt:default-token-lifetime := 30*24*60*60; (:xs:dayTimeDuration("P30D");:)
declare variable $jwt:header := jwt:encode(map { "alg": "HS256", "typ": "JWT" });


declare function jwt:instance ($secret as xs:string, $lifetime as xs:integer) as map(*) {
    let $now := current-dateTime() => jwt:dateTime-to-epoch()

    return
        map {
            "create" : jwt:create(?, $now, $secret),
            "read" : jwt:read(?, $secret, $lifetime)
        }
};

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

declare function jwt:sign ($data as xs:string, $secret as xs:string) as xs:string {
    crypto:hmac($data, $secret, "HMAC-SHA-256", "base64")
    => jwt:base64-url-safe()
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
        else (error())
};


declare function jwt:dateTime-to-epoch($dateTime as xs:dateTime) as xs:integer {
    ($dateTime - $jwt:epoch-start) div xs:dayTimeDuration('PT1S')
};

declare function jwt:epoch-to-dateTime($ts as xs:integer) as xs:dateTime {
    $jwt:epoch-start + xs:dayTimeDuration(concat("PT", $ts, "S"))
};

declare
function jwt:encode ($data as item()) as xs:string {
    $data
        => serialize(map { "method": "json" })
        => util:base64-encode(true())
        => jwt:base64-url-safe()
};

declare
function jwt:decode ($base64 as xs:string) as item()? {
    $base64
        (: base64-decode might to be able to handle url-safe encoded data :)
        => translate('-_', '/+')
        => jwt:base64-pad()
        => util:base64-decode()
        => parse-json()
};

(:~
 : add padding (= or ==) otherwise util:base64-decode() throws an error
 :)
declare %private
function jwt:base64-pad ($data as xs:string) as xs:string {
    let $mod4 := string-length($data) mod 4
    let $pad :=
        switch ($mod4)
            case 2 return "=="
            case 3 return "="
            default return ""

    return 
        $data || $pad
};

(:~
 : convert base64 string to url-safe without padding
 : replace / and + with - and _
 : omit padding (=)
 : @see https://tools.ietf.org/html/rfc4648
 :)
declare %private
function jwt:base64-url-safe ($base64 as xs:string) as xs:string {
    $base64 => translate('+/=', '-_')
};
