# PKCS12Converter
PKCS12Converter is a quick hack to convert a PKCS12 key pair into a OpenPGP key pair defined in RFC 4880. 
Provided one PKCS12 key pair it will generate one OpenPGP public and one OpenPGP secret key.
If provided a "master key pair" and a second PKCS12 key pair, it will construct a key ring with the OpenPGP "master key pair" and a sub key. The key properties are defined in the KeySettings.prperties file. There are 4 categories predefined: The master, sining, encryption and authentication key pair.

## Why?
I'm using X509 certificates for authentication (mutual ssl/tls client certificate based authentication)  and encryption/signing in the area of secure email communication (S/MIME).
On the other hand I'm using GnuPG key pairs for the ssh authentication and encrypting and signing data.
The target was to have one smart card (OpenPGP card) for both worlds. 
For me it turned out, to be the easiest way to generate PKCS12 key pairs with X509 certificates. The These can be converted to OpenPGP key pairs. The OpenPGP key pairs and PKCS12 key pairs with X509 certificates are bases on the very same RSA key pair.
The private keys and the certificates can be load on the card for the dual usage.

## Build
Retrieve the source from the git repository:
  git clone https://

Build the project with gradle:
  gradle build

## Run

To convert a single PKCS12 file into a OpenPGP key pair run:
  java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --type authentication --in auth.p12

Note there are 3 predefined templates for the key signatures:
 - auth(thenticaion) for authentication key pairs
 - sig(ning) for signing key pairs
 - enc(ryption) for encryption keys
All key properties are in the KeySettings.properties file defined. You can generate your own properties file or adapt the properties to your needs.

In case you want generate a key ring with sub keys run the converter as follows: 

Sample for a key ring with sub key:
  java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --masterkey master.p12 --type auth --in auth.p12 --uid Dagobert
In this sample "auth.p12" will become the sub key of master.p12. The master key has its own key setting, which are also defined in KeySettings.properties.



 
  