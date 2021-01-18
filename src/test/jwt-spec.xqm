xquery version "3.1";


module namespace jwt-spec="http://existsolutions.com/ns/jwt-spec";


import module namespace jwt="http://existsolutions.com/ns/jwt";


declare namespace test="http://exist-db.org/xquery/xqsuite";


(:~
 : read from a safe place like
 : /db/security/config.xml
 :)
declare variable $jwt-spec:secret := "my very special secret!!111";

(: 1 minute :)
declare variable $jwt-spec:token-lifetime := 60;
declare variable $jwt-spec:now := current-dateTime() => jwt:dateTime-to-epoch();

declare variable $jwt-spec:payload := map { "a": "b", "c": map {1: 2}, "d": [ 3, "e"] };

declare variable $jwt-spec:real-u :=
<sm:id>
    <sm:username>admin</sm:username>
    <sm:groups><sm:group>dba</sm:group></sm:groups>
</sm:id>
;

declare variable $jwt-spec:user-payload := map {
    "name": $jwt-spec:real-u/sm:username/text(),
    "groups": array { 
        $jwt-spec:real-u//sm:group/text()
    }
};

declare
    %private
function jwt-spec:instance () {
    jwt:instance($jwt-spec:secret, $jwt-spec:token-lifetime)
}; 

declare 
    %test:assertTrue
function jwt-spec:valid () {
    let $instance := jwt-spec:instance()
    let $token := $instance?create($jwt-spec:payload)
    let $decoded-payload := $instance?read($token)
    return
        exists($decoded-payload) and
        $decoded-payload instance of map(*)
};

declare 
    %test:assertTrue
function jwt-spec:correct-payload () {
    let $instance := jwt-spec:instance()
    let $token := $instance?create($jwt-spec:payload)
    let $payload := $instance?read($token)
    return
        $payload?a eq "b" and
        $payload?c?1 eq 2 and
        $payload?d?1 eq 3 and
        $payload?d?2 eq "e"
};

declare 
    %test:assertEquals("admin")
function jwt-spec:user-payload-user () {
    let $instance := jwt-spec:instance()
    let $token := $instance?create($jwt-spec:user-payload)
    let $payload := $instance?read($token)
    return
        $payload?name
};

declare 
    %test:assertTrue
function jwt-spec:user-payload-groups () {
    let $instance := jwt-spec:instance()
    let $token := $instance?create($jwt-spec:user-payload)
    let $payload := $instance?read($token)
    return
        "dba" = $payload?groups?* 
};

declare 
    %test:assertTrue
function jwt-spec:payload-has-valid-iat () {
    let $token := jwt:create($jwt-spec:payload, $jwt-spec:now, $jwt-spec:secret)
    let $payload := jwt:read($token, $jwt-spec:secret, $jwt-spec:token-lifetime)
    let $iat := $payload?iat
    return
        $jwt-spec:now = $iat 
};

(:~
 : deliberately create a token that is too old 
 :)
declare
    %test:assertError("too-old")
function jwt-spec:old-token () {
    let $instance := jwt-spec:instance()
    let $past := $jwt-spec:now - $jwt-spec:token-lifetime - 1 (: set issued-at a second too far in the past :)
    let $token := jwt:create($jwt-spec:payload, $past, $jwt-spec:secret)

    return $instance?read($token)
};

(:~
 : deliberately create a token that is too old 
 :)
declare
    %test:assertError("future-date")
function jwt-spec:future-token () {
    let $instance := jwt-spec:instance()
    let $future := $jwt-spec:now + 10 (: set issued-at ten seconds in the future :)
    let $token := jwt:create($jwt-spec:payload, $future, $jwt-spec:secret)

    return $instance?read($token)
};

(:~
 : handle arbitrary token 
 : NOTE: this test fails with an NPE while calling it from Xquery directly works
 :)
declare
    %test:pending
    %test:assertError("invalid-header")
function jwt-spec:arbitrary-token-with-separators () {
    let $instance := jwt-spec:instance()
    return $instance?read("asdfklajdf.ladj.aldj")
};

(:~
 : handle arbitrary token 
 :)
declare
    %test:assertError("invalid-token")
function jwt-spec:random-token () {
    let $instance := jwt-spec:instance()
    return $instance?read("}Débi:#@+===R{123123S@#R.aGdsÜG$@{FD")
};


(:~
 : handle empty token 
 :)
declare
    %test:assertError("invalid-token")
function jwt-spec:emtpy-token () {
    let $instance := jwt-spec:instance()
    return $instance?read("")
};

(:~
 : handle no payload 
 :)
declare
    %test:assertError("err:XPTY0004")
function jwt-spec:no-payload () {
    let $instance := jwt-spec:instance()
    return $instance?create(())
};

(:~
 : handle empty payload 
 :)
declare
    %test:assertTrue
function jwt-spec:empty-payload () {
    let $instance := jwt-spec:instance()
    return $instance?create(map {})
};
