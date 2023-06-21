# Java Library for SD-JWT

## Overview

This is a Java library for the "**Selective Disclosure for JWTs (SD-JWT)**"
specification. The following features are provided.

- Create a Disclosure.
- Parse a Disclosure.
- Create an SD-JWT.
- Parse an SD-JWT.
- Create a `Map` instance that contains the "`_sd`" array.
- Create a `Map` instance that represents a selectively-disclosable array element.
- Encode a map or a list recursively.
- Decode a map or a list recursively.

## License

  Apache License, Version 2.0

## Maven

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>sd-jwt</artifactId>
    <version>${sd-jwt.version}</version>
</dependency>
```

Check the [CHANGES.md](CHANGES.md) file to know the latest version.

## Source Code

  <code>https://github.com/authlete/sd-jwt</code>

## JavaDoc

  <code>https://authlete.github.io/sd-jwt</code>

## Description

### Disclosure

**Disclosure** is a basic component in the SD-JWT specification. A Disclosure
consists of a salt, a claim name and a claim value (for an object property),
or consists of a salt and a claim value (for an array element).

The `Disclosure` class in this library corresponds to the concept of Disclosure.
The class provides a constructor that takes 3 arguments which correspond to a
salt, a claim name and a claim value, respectively.

```java
// Code Snippet 1: Disclosure's 3-argument constructor

// Parameters for the 3-argument constructor of Disclosure.
String salt       = "_26bc4LT-ac6q2KI6cBW5es";
String claimName  = "family_name";
Object claimValue = "Möbius";

// Create a Disclosure instance with the parameters.
Disclosure disclosure = new Disclosure(salt, claimName, claimValue);
```

The SD-JWT specification recommends that a salt have 128-bit or higher entropy
and be base64url-encoded. If you don't want to bother with salt generation,
you can let the `Disclosure` class auto-generate a salt by using the 2-argument
constructor.

```java
// Code Snippet 2: Disclosure's 2-argument constructor

// Parameters for the 2-argument constructor of Disclosure.
String claimName  = "family_name";
Object claimValue = "Möbius";

// Create a Disclosure instance with the parameters.
Disclosure disclosure = new Disclosure(claimName, claimValue);
```

The SD-JWT specification defines a procedure to convert a combination of a
salt, a claim name and a claim value into a single string in the base64url
format. The steps of the procedure are as follows.

1. Create an array having a salt, a claim name and a claim value in this order.
2. Convert the array into JSON.
3. Convert the JSON into a UTF-8 byte sequence.
4. Base64url-encode the byte sequence.

Applying this procedure to the combination of parameters in Code Snippet 1 will
generate the following string (It is assumed here that the JSON does not
include any redundant white spaces).

```
WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd
```

A base64url string generated in this way is called "Disclosure".

You don't have to execute the steps one by one manually because the
`getDisclosure()` method of the `Disclosure` class executes the steps on behalf
of you. Also, the `toString()` method returns the same value as the
`getDisclosure()` method does.

```java
// Code Snippet 3: String representation of Disclosure

// Get the string representation of the Disclosure.
String disclosureA = disclosure.getDisclosure();
String disclosureB = disclosure.toString();

// disclosureA and disclosureB hold the same value.
```

If you have a Disclosure's string representation, you can construct a
`Disclosure` instance from the string by using the `parse(String)` method
of the `Disclosure` class.

```java
// Code Snippet 4: Parsing a Disclosure's string representation

Disclosure disclosure = Disclosure.parse(
    "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");
```

### Disclosure Digest

The basic idea to make claims in a JWT selectively-disclosable is to remove
target claims from the JWT and insert digest values of the claims in exchange
and then send the claims along with the JWT.

```mermaid
flowchart LR
    node1(Claim in JWT) --> node2(Digest in JWT)
    node1               --> node3(Claim)
```

Because actual claims cannot be deduced from their digest values, a receiver
of the JWT cannot know actual claims only with the JWT. The receiver has to
receive actual claims with the JWT.

From a perspective of the sender of the JWT, the mechanism enables the sender
to select claims to disclose by choosing claims to send with the JWT.

The SD-JWT specification uses digest values of Disclosures as digest values
in a JWT and Disclosures as actual claims sent with the JWT.

```mermaid
flowchart LR
    node1(Claim in JWT) --> node2(Digest of Disclosure in JWT)
    node1               --> node3(Disclosure)
```

When a digest value of Disclosure is embedded in a JSON object, it is listed
as an element in the "`_sd`" array. The name of the array, i.e., "`_sd`", is
defined in the SD-JWT specification for the purpose.

For example, a "`family_name`" claim in a JSON object like below

```json
{
  "family_name": "Möbius"
}
```

will be replaced with a digest value like below.

```json
{
  "_sd": [
    "TZjouOTrBKEwUNjNDs9yeMzBoQn8FFLPaJjRRmAtwrM"
  ]
}
```

The procedure to compute the digest value of a Disclosure to be listed in the
"`_sd`" array is defined as follows.

1. Compute a digest value over the US-ASCII bytes of the base64url-encoded Disclosure.
2. Base64url-encode the digest value.

The digest value suitable for being embedded can be computed by using the
`digest()` method or the `digest(String)` method of the `Disclosure` class.
The no-argument `digest()` method uses `sha-256` as a hash algorithm while
the 1-argument `digest(String)` method accepts a hash algorithm to use
(cf. [IANA: Named Information Hash Algorithm Registry][HASH_ALGORITHM_REGISTRY]).

```java
// Code Snippet 5: Disclosure digest

// Compute a digest with the hash algorithm "sha-256".
String digestSha256 = disclosure.digest();

// Compute a digest with a specified hash algorithm.
String digestSha512 = disclosure.digest("sha-512");
```

### Disclosure for Array Element

When there is an array like below,

```json
{
  "array": [ "element0", "element1" ]
}
```

a Disclosure for the whole array can be created as follows.

```java
// Code Snippet 6: Disclosure for the whole array.
List<String> array = List.of("element0", "element1");
Disclosure disclosure = new Disclosure("array", array);
```

On the other hand, a disclosure can be created for each array element if
you wish. In this case, a Disclosure consists of a salt and an array
element value.

```java
// Code Snippet 7: Disclosures for array elements

// Create a disclosure for an array element. The 1-argument constructor
// of the Disclosure class is used here. The constructor takes the value
// of an array element. Disclosures for array elements do not require a
// claim name.
Disclosure disclosure0 = new Disclosure("element0");

// If a salt needs to be specified explicitly, the 3-argument constructor
// should be used with 'claimName' null.
Disclosure disclosure1 = new Disclosure(salt, null, "element1");
```

An array element can be made selectively-disclosable by replacing it with a
JSON object that has a sole key-value pair whose key is `...` (literally
three dots) and whose value is the digest of the disclosure that corresponds
to the array element. Below is an example.

```json
{
  "array": [ "element0", {"...": "11sTIzcE9RxK90IvzjPpWe_s7iQm1Da-AUk_VT45DMo"} ]
}
```

The `Disclosure` class provides the `toArrayElement()` method and the
`toArrayElement(String hashAlgorithm)` method that create a `Map` instance
representing a selectively-disclosable array element.

```java
// Code Snippet 8: Selectively-disclosable array element

// Create a Map instance that represents a selectively-disclosable
// array element.
Map<String, Object> element = disclosure1.toArrayElement();

// element -> {"...": "11sTIzcE9RxK90IvzjPpWe_s7iQm1Da-AUk_VT45DMo"}
```

### Selective Disclosure Object

The `SDObjectBuilder` class in this library is a utility class to create a
`Map` instance that represents a JSON object which may contain the "`_sd`"
array.

A typical flow of using the `SDObjectBuilder` class is as follows.

1. Create an `SDObjectBuilder` instance.
2. Add normal claims as necessary.
3. Add digests of Disclosures as necessary.
4. Call the `build()` method to create a `Map` instance.

```java
// Code Snippet 9: Usage of SDObjectBuilder

// Create an SDObjectBuilder instance.
SDObjectBuilder builder = new SDObjectBuilder();

// Add a normal claim.
builder.putClaim("my_claim_name", "my_claim_value");

// Add a digest of Disclosure.
Disclosure disclosure = new Disclosure(
    "_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius");
builder.putSDClaim(disclosure);

// Create a Map instance.
Map<String, Object> map = builder.build();
```

The code snippet above will create a `Map` instance that is equivalent to the
following JSON.

```json
{
  "my_claim_name": "my_claim_value",
  "_sd": [
    "TZjouOTrBKEwUNjNDs9yeMzBoQn8FFLPaJjRRmAtwrM"
  ]
}
```

The hash algorithm used to compute digests of Disclosures can be specified by
using the 1-argument constructor of the `SDObjectBuilder` class. The no-argument
constructor uses "`sha-256`" as the hash algorithm.

```java
// Code Snippet 10: Specifying a hash algorithm for SDObjectBuilder to use

// Create an SDObjectBuilder instance with a hash algorithm.
SDObjectBuilder builder = new SDObjectBuilder("sha-512");
```

The name of the hash algorithm can be embedded in the `Map` instance by calling
the 1-argument variant of the `build` method with `true`.

```java
// Code Snippet 11: Including the name of the hash algorithm

// Create a Map instance with the name of the hash algorithm included.
Map<String, Object> map = builder.build(true);
```

`_sd_alg` is used as the name of the claim that holds the name of the hash
algorithm. The following JSON is an example including the `_sd_alg` claim and
a digest value computed with the hash algorithm "`sha-512`".

```json
{
  "_sd": [
    "j35wlGQlyQ8b4OE3Py6l3AAvOskjcNOxj0SsiVSrVdmVs8bapSUelViRDbmlntFABkp6_zSz1fA-dlWGUxGpEA"
  ],
  "_sd_alg": "sha-512"
}
```

The `putSDClaim` method has some other variants than `putSDClaim(Disclosure)`
as listed below.

- `putSDClaim(String claimName, Object claimValue)`
- `putSDClaim(String salt, String claimName, Object claimValue)`

They are aliases of `putSDClaim(Disclosure)`, meaning that they internally
create a `Disclosure` instance and then call the `putSDClaim(Disclosure)`
method with the `Disclosure` instance.

### Decoy Digest

From the SD-JWT specification:

> An Issuer MAY add additional digests to the SD-JWT that are not associated
> with any claim. The purpose of such "decoy" digests is to make it more
> difficult for an attacker to see the original number of claims contained
> in the SD-JWT. Decoy digests MAY be added both to the _sd array for objects
> as well as in arrays.

The `SDObjectBuilder` class has the `putDecoyDigest()` method that adds a
decoy digest and the `putDecoyDigests(int)` method that adds the specified
number of decoy digests.

```java
// Code Snippet 12: Decoy digests

// Add a decoy digest.
builder.putDecoyDigest();

// Add the specified number of decoy digests.
builder.putDecoyDigests(3);
```

### Credential JWT

This library calls a JWT whose payload may contain the "`_sd"` array and/or
a disclosable array element somewhere **Credential JWT**. A credential JWT
is always put at the head of an SD-JWT.

This library deliberately avoids providing utility classes to build JWTs
and instead provides only a small utility (`SDObjectBuilder`) to help build
the payload part of an SD-JWT.

As this library does not get involved in the process of JWT generation, you
can use any JWT library you like.

The following is an example of generating an SD-JWT using the
"[Nimbus JOSE + JWT][NIMBUS_JOSE_JWT]" library.

```java
// Code Snippet 13: Credential JWT generation

import java.util.*;
import com.authlete.sd.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

public class CredentialJwtGenerationExample
{
    public static void main(String[] args) throws Exception
    {
        //--------------------------------------------------
        // Using the SD-JWT library
        //--------------------------------------------------

        // Create a Disclosure for the claim "nickname":"Taka".
        Disclosure disclosure = new Disclosure("nickname", "Taka");

        // Create an SDObjectBuilder instance to prepare the payload part of
        // a credential JWT. "sha-256" is used as a hash algorithm to compute
        // digest values of Disclosures.
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put the digest value of the Disclosure.
        builder.putSDClaim(disclosure);

        // Create a Map instance that represents the payload part of a
        // credential JWT. The 'claims' map contains the "_sd" array.
        // The size of the array is 1.
        Map<String, Object> claims = builder.build();

        //--------------------------------------------------
        // Using the Nimbus JOSE + JWT library
        //--------------------------------------------------

        // Prepare the header part of a credential JWT.
        // The header represents {"alg":"ES256","typ":"vc+sd-jwt"}.
        JWSHeader header =
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("vc+sd-jwt")).build();

        // Prepare the payload part of a credential JWT.
        //
        // Just converting the Map instance to a JWTClaimsSet instance which
        // is to be passed to the constructor of the SignedJWT class below.
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);

        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, claimsSet);

        // Create a private key to sign the credential JWT.
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        // Create a signer that signs the credential JWT with the private key.
        JWSSigner signer = new ECDSASigner(privateKey);

        // Let the signer sign the credential JWT.
        jwt.sign(signer);

        // Print the JWT in the JWS compact serialization format.
        System.out.println(jwt.serialize());
    }
}
```

The example code above generates a credential JWT (a kind of JWT) like below.

```
eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiVzVEX3dSam9qbUZvYUNpeFVLNVJXSFRsVE1TYnNqZHhHU3daYTltXzZ1RSJdfQ.IiJyysrsFqjyv2n9gmjQehvmxYY5g2-nR_mgtn1BeHkiWTYuK_UEoLn00nSteX1cFj1n8waEYwVO-ytnnTzbKg
```

The payload part of the credential JWT holds the "`_sd`" array like below.

```json
{
  "_sd": [
    "W5D_wRjojmFoaCixUK5RWHTlTMSbsjdxGSwZa9m_6uE"
  ]
}
```

### Nested Claims

Claims in the payload part of a JWT may have nested claims like the `address`
claim in the following example.

```json
{
  "address": {
    "street_address": "Schulstr. 12",
    "locality": "Schulpforta",
    "region": "Sachsen-Anhalt",
    "country": "DE"
  }
}
```

An SD-JWT issuer may make one Disclosure for such an enveloping claim or may
make a Disclosure for each nested claim.

The following example generates one Disclosure for the `address` claim.

```java
// Code Snippet 14: Disclosure per enveloping claim

// Prepare a Map instance that represents the value of the "address" claim.
Map<String, Object> address = new HashMap<>();
address.put("street_address", "Schulster. 12");
address.put("locality", "Schulpforta");
address.put("region", "Sachsen-Anhalt");
address.put("country", "DE");

// Put the digest of the Disclosure for the "address" claim.
SDObjectBuilder builder = new SDObjectBuilder();
builder.putSDClaim("address", address);

// Create a Map instance that represents the whole JSON object.
Map<String, Object> claims = builder.build();
```

The `claims` map created on the last line represents JSON like below.

```json
{
  "_sd": [
    "l594fCG-zM754g70Y7kLtRWnNGVDvwB49g-T8Y2SzsE"
  ]
}
```

On the other hand, the following example generates a Disclosure for each nested
claim under the `address` claim.

```java
// Code Snippet 15: Disclosure per nested claim

// Prepare a Map instance that represents the value of the "address" claim.
// A digest is created for each claim. As a result, the "_sd" array will
// contain 4 digest values.
SDObjectBuilder builder = new SDObjectBuilder();
builder.putSDClaim("street_address", "Schulster. 12");
builder.putSDClaim("locality", "Schulpforta");
builder.putSDClaim("region", "Sachsen-Anhalt");
builder.putSDClaim("country", "DE");
Map<String, Object> address = builder.build();

// Create a Map instance that represents the whole JSON object.
Map<String, Object> claims = new HashMap<>();

// Put the "address" claim whose value contains the "_sd" array.
claims.put("address", address);
```

The `claims` map represents JSON like below.

```json
{
  "address": {
    "_sd": [
      "cklfcWaq25X9AsPb1w0YL8VCmTV-zoRCDJfNBiZ922c",
      "lCVUh6cfGUPG7R4sWbyZYvGmzkN_ccXfutlQPO6Yz9s",
      "oW1S6124anRtUQ8WI17E1ZxPBSMXzAntOOfrighlzbo",
      "sq0JRi1z7abL156-hYZ6WsTkKxHyxCWGEpt5AQvbqSY"
    ]
  }
}
```

### SD-JWT

An SD-JWT consists of a credential JWT, disclosures and an optional binding
JWT. The string representation of an SD-JWT is built by concatenating these
elements with the delimiter tilde `~`. If a binding JWT is omitted, the
string representation of an SD-JWT ends with `~`.

```
<Credential-JWT>~<Disclosure 1>~...~<Disclosure N>~[<Binding-JWT>]
```

The `SDJWT` class in this library represents an SD-JWT. The class has the
following two constructors.

1. `SDJWT(String credentialJwt, Collection<Disclosure> disclosures)`
2. `SDJWT(String credentialJwt, Collection<Disclosure> disclosures, String bindingJwt)`

The values of the arguments given to the constructors can be obtained by the
following instance methods, respectively.

- `String getCredentialJwt()`
- `List<Disclosure> getDisclosures()`
- `String getBindingJwt()`

The `SDJWT` class overrides the `toString()` method so that it can return the
string representation of the SD-JWT.

```java
// Code Snippet 16: String representation of an SD-JWT

// Create an instance of the SDJWT class. In this example, a binding JWT
// is omitted.
SDJWT sdJwt = new SDJWT(credentialJwt, List.of(disclosure));

// Print the string representation of the SD-JWT.
System.out.println(sdJwt.toString());
```

The following is an example output that the above code snippet may generate.
The output string contains two tildes. One is in between the credential JWT
and the disclosure, and the other is placed at the end.

```
eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiRDFnTU5Kd0JKV0FKR0dxWUV1TUZ4OU5WX2xGelhCT2ItTDk0ZENfX2NadyJdfQ.k4eSYQpu-9-bQsOsfer_gRqFvgkBQ-Sd-ZG2dBND4LDtOKpcXLCESnqnxBLobTEAxbIrypnIfNxEiS6TnR-6jQ~WyJJM0NsMFYtcmtMNmdVVFlxS3VEMV93Iiwibmlja25hbWUiLCJUYWthIl0~
```

The `SDJWT` class provides the `parse(String)` method. An `SDJWT` instance
can be built from the string representation of an SD-JWT.

```java
// Code Snippet 17: Parsing a string as an SD-JWT

// The string representation of an SD-JWT.
String input = "eyJ...6jQ~WyJ...Il0~";

// Parse the string.
SDJWT sdJwt = SDJWT.parse(input);
```

## SDObjectEncoder

The `SDObjectEncoder` class is a utility to make elements in a map or a list
selectively-disclosable recursively.

The class uses the `SDObjectBuilder` class internally and adds decoy digests
automatically unless decoy magnification ratio is set to 0.0 through
constructors or the `setDecoyMagnification(double min, double max)` method.

The following is a simple example of `SDObjectEncoder`.

```java
// Code Snippet 18: Usage of SDObjectEncoder

// Prepare a dataset.
Map<String, Object> originalMap = Map.of(
        "key-1", "abc",
        "key-2", 123
);

// Create an encoder with the default parameters.
SDObjectEncoder encoder = new SDObjectEncoder();

// Encode the dataset.
Map<String, Object> encodedMap = encoder.encode(originalMap);

// Disclosures yielded as a result of the encoding process.
List<Disclosure> disclosures = encoder.getDisclosures();
```

The encoded map (`encodedMap`) by the code snippet above will have a content
like below. In this example, the `"_sd"` array contains two digests of
Disclosures that correspond to the two properties in the input map
(`originalMap`) and a decoy digest which was automatically generated.

```json
{
  "_sd": [
    "3xbuhktzQVLGmk0KknsLUDDARQ43ROf7bSTXW89wFUs",
    "YA4Io-RgBljWN_c0VZz1DxK18sfAPn4rxgfuQKhSVPQ",
    "tUCKvqg8OLmfTc-grCpCY5mqW_7Zy5Fx6shouLxpyKM"
  ],
  "_sd_alg": "sha-256"
}
```

The encoding process yields Disclosures as a result. The `getDisclosures()`
method returns the list of Disclosures. The following are contents of
Disclosures corresponding to the above code.

| Digest                                        | Salt                     | Claim Name | Claim Value |
|:---------------------------------------------:|:------------------------:|:----------:|:-----------:|
| `YA4Io-RgBljWN_c0VZz1DxK18sfAPn4rxgfuQKhSVPQ` | `exARSKhJVFUAlpKouwY5RQ` | `key-2`    | `123`       |
| `tUCKvqg8OLmfTc-grCpCY5mqW_7Zy5Fx6shouLxpyKM` | `1TWRUu8-21GkX8wltgXYZA` | `key-1`    | `"abc"`     |

## SDObjectDecoder

The `SDObjectDecoder` class is a utility to decode selectively-disclosable
elements in a map or a list recursively.

The `decode` methods of the class take an encoded dataset and a list of
Disclosures. If all the Disclosures are passed, the original dataset is
restored.

```java
// Code Snippet 19: Usage of SDObjectDecoder

// Create a decoder.
SDObjectDecoder decoder = new SDObjectDecoder();

// Decode the encoded map with all the Disclosures.
// The original dataset should be restored.
Map<String, Object> decodedMap = decoder.decode(encodedMap, disclosures);
```

On the other hand, if a subset of Disclosures is passed, only claims that
correspond to the passed Disclosures are restored.

```java
// Code Snippet 20: Disclosing claims selectively

// Prepare a subset of Disclosures which contains only the Disclosure
// that corresponds to the "key-1":"abc".
List<Disclosure> subset = disclosures.stream()
        .filter(d -> "key-1".equals(d.getClaimName()))
        .collect(Collectors.toList());

// Decode the encoded map with the subset of Disclosures.
decodedMap = decoder.decode(encodedMap, subset);
```

The resultant decoded map (`decodedMap`) will have a content below. It contains
only the key-value pair `"key-1":"abc"` and does not contain the key-value pair
`"key-2":123`.

```json
{
  "key-1": "abc"
}
```

## References

- SD-JWT Datatracker: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- SD-JWT GitHub: https://github.com/oauth-wg/oauth-selective-disclosure-jwt

## Contact

Authlete Contact Form: https://www.authlete.com/contact/

[HASH_ALGORITHM_REGISTRY]: https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
[NIMBUS_JOSE_JWT]: https://connect2id.com/products/nimbus-jose-jwt
