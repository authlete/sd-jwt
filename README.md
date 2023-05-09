# Java Library for SD-JWT

## Overview

This is a Java library for the "**Selective Disclosure for JWTs (SD-JWT)**"
specification. The following features are provided.

- Create a Disclosure.
- Parse a Disclosure.
- Create a `Map` instance that contains the "`_sd`" array.
- Create a Combined Format for Issuance / Presentation.
- Parse a Combined Format for Issuance / Presentation.

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
consists of a salt, a claim name and a claim value.

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
you wish. In this case, a Disclosure consists of a salt, an array name,
an array index, and an array element value.

```java
// Code Snippet 7: Disclosures for array elements.
Disclosure disclosure0 = new Disclosure("array", 0, "element0");
Disclosure disclosure1 = new Disclosure("array", 1, "element1");
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
// Code Snippet 8: Usage of SDObjectBuilder

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
// Code Snippet 9: Specifying a hash algorithm for SDObjectBuilder to use

// Create an SDObjectBuilder instance with a hash algorithm.
SDObjectBuilder builder = new SDObjectBuilder("sha-512");
```

The name of the hash algorithm can be embedded in the `Map` instance by calling
the 1-argument variant of the `build` method with `true`.

```java
// Code Snippet 10: Including the name of the hash algorithm

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
- `putSDClaim(String claimName, int claimIndex, Object claimValue)`
- `putSDClaim(String salt, String claimName, int claimIndex, Object claimValue)`

They are aliases of `putSDClaim(Disclosure)`, meaning that they internally
create a `Disclosure` instance and then call the `putSDClaim(Disclosure)`
method with the `Disclosure` instance.

### Decoy Digest

From the SD-JWT specification:

> An Issuer MAY add additional digests to the SD-JWT that are not associated
> with any claim. The purpose of such "decoy" digests is to make it more
> difficult for an attacker to see the original number of claims contained
> in the SD-JWT.

The `SDObjectBuilder` class has the `putDecoyDigest()` method that adds a
decoy digest and the `putDecoyDigests(int)` method that adds the specified
number of decoy digests.

```java
// Code Snippet 11: Decoy digests

// Add a decoy digest.
builder.putDecoyDigest();

// Add the specified number of decoy digests.
builder.putDecoyDigests(3);
```

### SD-JWT

Roughly speaking, a JWT whose payload contains the "`_sd`" array somewhere
can be said **SD-JWT**.

This library intentionally avoids providing utility classes to build JWTs
and instead provides only a small utility (`SDObjectBuilder`) to help build
the payload part of an SD-JWT.

As this library does not get involved in the process of JWT generation, you
can use any JWT library you like.

The following is an example of generating an SD-JWT using the
"[Nimbus JOSE + JWT][NIMBUS_JOSE_JWT]" library.

```java
// Code Snippet 12: SD-JWT generation

import java.util.*;
import com.authlete.sd.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

public class SDJwtGenerationExample
{
    public static void main(String[] args) throws Exception
    {
        //--------------------------------------------------
        // Using the SD-JWT library
        //--------------------------------------------------

        // Create a Disclosure for the claim "nickname":"Taka".
        Disclosure disclosure = new Disclosure("nickname", "Taka");

        // Create an SDObjectBuilder instance to prepare the payload part of
        // an SD-JWT. "sha-256" is used as a hash algorithm to compute digest
        // values of Disclosures.
        SDObjectBuilder builder = new SDObjectBuilder();

        // Put the digest value of the Disclosure.
        builder.putSDClaim(disclosure);

        // Create a Map instance that represents the payload part of an SD-JWT.
        // The 'claims' map contains the "_sd" array. The size of the array is 1.
        Map<String, Object> claims = builder.build();

        //--------------------------------------------------
        // Using the Nimbus JOSE + JWT library
        //--------------------------------------------------

        // Prepare the header part of an SD-JWT.
        // The header represents {"alg":"ES256","typ":"JWT"}.
        JWSHeader header =
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT).build();

        // Prepare the payload part of an SD-JWT.
        //
        // Just converting the Map instance to a JWTClaimsSet instance which
        // is to be passed to the constructor of the SignedJWT class below.
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);

        // Create an SD-JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, claimsSet);

        // Create a private key to sign the SD-JWT.
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        // Create a signer that signs the SD-JWT with the private key.
        JWSSigner signer = new ECDSASigner(privateKey);

        // Let the signer sign the SD-JWT.
        jwt.sign(signer);

        // Print the JWT in the JWS compact serialization format.
        System.out.println(jwt.serialize());
    }
}
```

The example code above generates an SD-JWT (a kind of JWT) like below.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiVGNrcnR4dUF3MXJNTWhZRmNYcHlKSFFfOFg1Q2thSnNPaUx3RDlQVmFFRSJdfQ.pPkAECyr4a1sdAX6_3KP_SCOksqHqMhcAv41wjMudxhs3TxdiHs_-XkILx5Si4w1QSXWXji2FGz3gObSTGN6Tw
```

The payload part of the SD-JWT holds the "`_sd`" array like below.

```json
{
  "_sd": [
    "TckrtxuAw1rMMhYFcXpyJHQ_8X5CkaJsOiLwD9PVaEE"
  ]
}
```

### Structured SD-JWT

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
// Code Snippet 13: Disclosure per enveloping claim

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
// Code Snippet 14: Disclosure per nested claim

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

### Combined Format

An SD-JWT is supposed to be transmitted with Disclosures. The SD-JWT
specification defines means to combine an SD-JWT and Disclosures into a single
string.

When an SD-JWT is issued, it is accompanied by all Disclosures. The SD-JWT and
all the Disclosures are concatenated using `~` (tilde) as delimiters and form
a single string. This format is called "**Combined Format for Issuance**".

```
<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>
```

On the other hand, when the legitimate holder of the SD-JWT wants to disclose
selectively some claims only, the holder sends the SD-JWT and some Disclosures
that correspond to the claims only. In this case, the SD-JWT and the selected
Disclosures are concatenated into a single string using the following format,
which is called "**Combined Format for Presentation**".

```
<SD-JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure M>~<optional Holder Binding JWT>
```

The Combined Format for Issuance and the Combined Format for Presentation can
be distinguished by checking the last part. When the string ends with `~` or a
JWT, it is Combined Format for Presentation. In other cases, it is Combined
Format for Issuance.

The `SDIssuance` class in this library represents Combined Format for Issuance
while the `SDPresentation` class represents Combined Format for Presentation.
The `SDCombinedFormat` class is the common super class of the two classes.

The constructor of the `SDIssuance` class takes two arguments. One is an SD-JWT
and the other is a collection of Disclosures.

```java
// Code Snippet 15: SDIssuance's constructor

// The 2-argument constructor of the SDIssuance class
public SDIssuance(String sdJwt, Collection<Disclosure> disclosures)
```

The `SDPresentation` class has a 3-argument constructor in addition to a
2-argument constructor. The 3-argument variant additionally accepts an optional
binding JWT.

```java
// Code Snippet 16: SDPresentation's 3-argument constructor

// The 3-argument constructor of the SDPresentation class
public SDPresentation(
    String sdJwt, Collection<Disclosure> disclosures, String bindingJwt)
```

As the common super class `SDCombinedFormat` is an abstract class, instances
of `SDCombinedFormat` cannot be created directly. But the class provides the
`parse(String)` method that parses a Combined Format and creates an instance
of either the `SDIssuance` class or the `SDPresentation` class.

The following code shows usage of methods of the `SDCombinedFormat` class.

```java
// Code Snippet 17: Usage of SDCombinedFormat methods

// SD-JWT
String sdJwt =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9." +
    "eyJfc2QiOlsiTHFFSGNJbGI2cnBZNGJqdnBDc0o5QlhWa3hOVXVrVmRMSmV1d3ZsYlIyVSJdfQ." +
    "xCg45cUhobOpJ0WGO6kI_OddOBkEW3fMHjfXyhegrY77mV4BzBNR7g6KI10ytVJJg1OGV6dSvuyfm8UBgmVrUg";

// Disclosure
String disclosure =
    "WyJsVElJbGdHbm5uTG9aYWpjY1RBNm5RIiwibmlja25hbWUiLCJUYWthIl0";

// Combined Format for Issuance (SD-JWT + 1 Disclosure)
String combinedFormat = String.format("%s~%s", sdJwt, disclosure);

// Parse the input.
SDCombinedFormat cf = SDCombinedFormat.parse(combinedFormat);

// The SD-JWT.
// 'sdJwt' and 'sdJwt2' have the same value.
String sdJwt2 = cf.getSDJwt();

// The unmodifiable list of Disclosures.
List<Disclosure> disclosures = cf.getDisclosures();

// If the returned object is an instance of SDIssuance.
if (cf.isIssuance())
{
    // The instance can be cast to SDIssuance.
    SDIssuance issuance = (SDIssuance)cf;
}

// If the returned object is an instance of SDPresentation.
if (cf.isPresentation())
{
    // The instance can be cast to SDPresentation.
    SDPresentation presentation = (SDPresentation)cf;

    // The binding JWT.
    String bindingJwt = presentation.getBindingJwt();
}

// The string representation of the Combined Format.
// 'combinedFormat' and 'combinedFormat2' have the same value.
String combinedFormat2 = cf.toString();
```

## References

- SD-JWT Datatracker: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- SD-JWT GitHub: https://github.com/oauth-wg/oauth-selective-disclosure-jwt

## Contact

Authlete Contact Form: https://www.authlete.com/contact/

[HASH_ALGORITHM_REGISTRY]: https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
[NIMBUS_JOSE_JWT]: https://connect2id.com/products/nimbus-jose-jwt
