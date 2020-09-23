xquery version "3.1";

import module namespace jwt = "http://existsolutions.com/ns/jwt";

(:~
 : read from a safe place like
 : /db/security/config.xml
 :)
declare variable $local:secret := "your-256-bit-secret";

(: 30 days :)
declare variable $local:token-lifetime := 30*24*60*60;

let $jwt := jwt:instance($local:secret, $local:token-lifetime)

let $real-u := sm:id()/sm:id/sm:real

let $payload := map {
    "name": $real-u/sm:username/text(),
    "groups": array { 
        $real-u//sm:group/text()
    }
}

let $token := $jwt?create($payload)

(: let $now := current-dateTime() => jwt:dateTime-to-epoch() :)
(: let $token := jwt:create($payload, $now, $local:secret) :)
(: this token is too old :)
(: let $payload := $jwt?read(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
):)

return (
    $payload,
    $token,
    $jwt?read($token)
)