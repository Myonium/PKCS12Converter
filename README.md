# PKCS12Converter
PKCS12Converter is a quick hack to convert a PKCS12 key pair into a OpenPGP key pair defined in RFC 4880. 
A PKCS12 key pair will be converted into a OpenPGP public and one OpenPGP secret key.
If provided a "master key pair" in addition to the PKCS12 key pair, it will construct a key ring with the OpenPGP "master key pair" and a sub key. The key properties are defined in the KeySettings.prperties file. There are 4 categories predefined: The master, signing, encryption and authentication key pair.

## Why?
I'm using X509 certificates for authentication (mutual ssl/tls client certificate based authentication)  and encryption/signing in the area of secure email communication (S/MIME).
On the other hand I'm using GnuPG key pairs for the ssh authentication and encrypting and signing data.
The target was to have one smart card (OpenPGP card) for both worlds. 
For me it turned out, to be the easiest way to generate PKCS12 key pairs with X509 certificates. The These can be converted to OpenPGP key pairs. The OpenPGP key pairs and PKCS12 key pairs with X509 certificates are based on the very same RSA key pair.
The private keys and the certificates can be load on the smart card for dual usage.

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

Note there are 3 predefined templates for key signatures:
 - auth(enticaion) for authentication key pairs
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
...

```
To load the OpenPGP key pair on the token run:
```
gpg2 --import [fingerprint_sec.bpg]
gpg2 --import [fingerprint_pub.bpg]
gpg2 --edit-key [fingerprint]
  toggle
  keytocard
```

When the public key is imported to gnupg you can sync with your smartcard to make gnupg aware of the private key on your card. This will generate the private key stub:
```
gpg2 --import [fingerprint_pub.bpg]
gpg2 --card-status
```

Possible errors:
 - If you should get the error "gpg: KEYTOCARD failed: Unusable secret key" the key was already sync'ed. Delete the private key stub under "~/.gnupg/private-keys-v1.d/[fingerprint.key]" to be able to import the private key.


 
Import certificate on OpenPGP compliant token:
```
pkcs15-init --verify-pin --store-certificate [pem encoded certificate] --auth-id 3 --id 3
```
or you can import the whole pkcs12 (private key, public key, X509 certificate):
```
pkcs15-init --delete-objects privkey,pubkey --id 3 --store-private-key [auth.p12] --format pkcs12 --auth-id 3 --verify-pin
```

Import certificate on yubico token:
``` 
yubico-piv-tool -s 9a -a import-certificate -i [auth.p12] -p [password]
```

To make your token available to PKCS11 compliant applications, you have to provide them PKCS11 library which understands your token. I'm using the opensc-pkcs11 library from the [OpenSC project](https://github.com/OpenSC/OpenSC).
E.g. to use the token with Firefox:
 - Open "Preferences" > Advanced > Security Devices
 - Click "Load"
 - Choose and name for the module e.g. OpenSC and the path to the opensc-pkcs11 library (e.g. on my linux "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", on my OSX "/opt/local/lib/opensc-pkcs11.so"). 
  