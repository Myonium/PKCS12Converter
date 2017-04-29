# PKCS12Converter
PKCS12Converter is a quick hack to convert a PKCS12 key pair into a OpenPGP key pair defined in RFC 4880. 
A PKCS12 key pair will be converted into a OpenPGP public and one OpenPGP secret key.
If provided a "master key pair" in addition to the PKCS12 key pair, it will construct a key ring with the OpenPGP "master key pair" and a sub key. The key properties are defined in the KeySettings.prperties file. There are 4 categories predefined: The master, signing, encryption and authentication key pair.

## Why?
I'm using X509 certificates for authentication (mutual ssl/tls client certificate based authentication)  and encryption/signing in the area of secure email communication (S/MIME).
On the other hand I'm using GnuPG key pairs for the ssh authentication and encrypting and signing data.
The target was to have one smart card (OpenPGP card) for both worlds. 
For me it turned out, to be the easiest way to generate PKCS12 key pairs with X509 certificates. The These can be converted to OpenPGP key pairs. The OpenPGP key pairs and PKCS12 key pairs with X509 certificates are bases on the very same RSA key pair.
The private keys and the certificates can be load on the card for the dual usage.

## Build
Retrieve the source from the git repository:
```
git clone https://github.com/Myonium/PKCS12Converter.git
```

Build the project with gradle:
```
gradle build
```

## Run

To convert a single PKCS12 file into a OpenPGP key pair run:
```
java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --type authentication --in auth.p12
```

Note there are 3 predefined templates for the key signatures:
 - auth(thenticaion) for authentication key pairs
 - sig(ning) for signing key pairs
 - enc(ryption) for encryption keys
All key properties are in the KeySettings.properties file defined. You can generate your own properties file or adapt the properties to your needs.

In case you want generate a key ring with sub keys run the converter as follows: 

Sample for a key ring with sub key:
```
java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --masterkey master.p12 --type auth --in auth.p12 --uid Myonium
```
In this sample "auth.p12" will become the sub key of master.p12. The master key has its own key setting, which are also defined in KeySettings.properties:
```
; General Setting
keyring.s2kcount=250

; Master Key Properties see RFC 4880
; Possible Certification Types are PGPSignature.POSITIVE_CERTIFICATION or PGPSignature.DEFAULT_CERTIFICATION
mk.certification=PGPSignature.POSITIVE_CERTIFICATION
mk.keyFlags=KeyFlags.SIGN_DATA,KeyFlags.CERTIFY_OTHER
mk.primaryUserId=true
mk.primaryUserId.mandatory=false
mk.trustSignature.value=3
mk.trustSignature.depth=0
mk.trustSignature.mandatory=true
mk.keyFlags.mandatory=false
mk.prefs.encAlgs=SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TRIPLE_DES 
mk.prefs.encAlgs.mandatory=false
mk.prefs.hashAlgs=HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256,HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160
mk.prefs.hashAlgs.mandatory=false
mk.prefs.comprAlgs=CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZIP
mk.prefs.comprAlgs.mandatory=false
mk.feature=Features.FEATURE_MODIFICATION_DETECTION
mk.feature.mandatory=false

; Signing Key Properties
sk.certification=PGPSignature.POSITIVE_CERTIFICATION
sk.keyFlags=KeyFlags.CERTIFY_OTHER,KeyFlags.SIGN_DATA
sk.keyFlags.mandatory=false
sk.primaryUserId=true
sk.primaryUserId.mandatory=true
sk.trustSignature.value=3
sk.trustSignature.depth=0
sk.trustSignature.mandatory=true
sk.prefs.encAlgs=SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TRIPLE_DES 
sk.prefs.encAlgs.mandatory=false
sk.prefs.hashAlgs=HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256,HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160
sk.prefs.hashAlgs.mandatory=false
sk.prefs.comprAlgs=CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZIP
sk.prefs.comprAlgs.mandatory=false
;sk.feature=Features.FEATURE_MODIFICATION_DETECTION
;sk.feature.mandatory=false

; Encryption Key Properties
ek.certification=PGPSignature.POSITIVE_CERTIFICATION
ek.keyFlags=KeyFlags.ENCRYPT_COMMS,KeyFlags.ENCRYPT_STORAGE
ek.keyFlags.mandatory=false
ek.primaryUserId=true
ek.primaryUserId.mandatory=true
ek.trustSignature.value=3
ek.trustSignature.depth=0
ek.trustSignature.mandatory=true
ek.prefs.encAlgs=SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TRIPLE_DES 
ek.prefs.encAlgs.mandatory=false
ek.prefs.hashAlgs=HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256,HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160
ek.prefs.hashAlgs.mandatory=false
ek.prefs.comprAlgs=CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZIP
ek.prefs.comprAlgs.mandatory=false
;ek.feature=Features.FEATURE_MODIFICATION_DETECTION
;ek.feature.mandatory=false

; Authentication Key Properties
ak.certification=PGPSignature.POSITIVE_CERTIFICATION
ak.keyFlags=KeyFlags.AUTHENTICATION
ak.keyFlags.mandatory=false
ak.primaryUserId=true
ak.primaryUserId.mandatory=true
;ak.trustSignature.value=3
;ak.trustSignature.depth=0
;ak.trustSignature.mandatory=true
ak.prefs.encAlgs=SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TRIPLE_DES 
ak.prefs.encAlgs.mandatory=false
ak.prefs.hashAlgs=HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256,HashAlgorithmTags.SHA1, HashAlgorithmTags.RIPEMD160
ak.prefs.hashAlgs.mandatory=false
;ak.prefs.comprAlgs=CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2, CompressionAlgorithmTags.ZIP
;ak.prefs.comprAlgs.mandatory=false
;ak.feature=Features.FEATURE_MODIFICATION_DETECTION

```



 
  