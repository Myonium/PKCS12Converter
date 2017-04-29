package org.bfe.gpg.utils;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;

import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;



public abstract class Utils {
	
	protected static Certificate certificate = null;
	protected static String fingerprint = null;
	protected static String pw ="";
	
	
	public static void exportSshKeyFromPublicKeyFile(String pkf){
		try{
			
			FileWriter fw =new FileWriter("ssh.txt");

			CertificateFactory cf= CertificateFactory.getInstance("X.509");
			FileInputStream inStream=new FileInputStream(pkf);
			X509Certificate cer =(X509Certificate) cf.generateCertificate(inStream);
			
			RSAPublicKey rsaPublicKey = (RSAPublicKey) cer.getPublicKey();
			
			ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
	        DataOutputStream dos = new DataOutputStream(byteOs);
	        dos.writeInt("ssh-rsa".getBytes().length);
	        dos.write("ssh-rsa".getBytes());
	        dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
	        dos.write(rsaPublicKey.getPublicExponent().toByteArray());
	        dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
	        dos.write(rsaPublicKey.getModulus().toByteArray());
	        String enc = Base64.toBase64String(byteOs.toByteArray());
	        System.out.println(enc);
	        fw.write("ssh-rsa ");
	        fw.write(enc);
	        if (cer.getSubjectAlternativeNames().isEmpty()){
	        	System.out.println("Adding DN "+ cer.getSubjectDN().getName());
	        	fw.write(" "+cer.getSubjectDN().getName()+"\n");
	        }else{
	        	Iterator it = cer.getSubjectAlternativeNames().iterator();
	        	StringBuffer name=new StringBuffer();
	        	Object  el = it.next();
	        	System.out.println(el.getClass().getName());
	        	name.append(el);
	        	while (it.hasNext()){
	        		name.append(",");
	        		name.append(it.next());
	        	}
	        	System.out.println("Adding Names "+ name);
	        	fw.write(" "+name+"\n");
	        }
	        fw.flush();
	        fw.close();
		} catch(IOException ioe){
			ioe.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	public static void exportSshKey(String alias){
		try{
			
			X509Certificate cer = (X509Certificate) certificate;
			RSAPublicKey rsaPublicKey = (RSAPublicKey) cer.getPublicKey();
			String filename ="ssh.txt";
			if (fingerprint !=null){
				filename=fingerprint + "_ssh.txt";
			}
			FileWriter fw =new FileWriter(filename);
			ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
	        DataOutputStream dos = new DataOutputStream(byteOs);
	        dos.writeInt("ssh-rsa".getBytes().length);
	        dos.write("ssh-rsa".getBytes());
	        dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
	        dos.write(rsaPublicKey.getPublicExponent().toByteArray());
	        dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
	        dos.write(rsaPublicKey.getModulus().toByteArray());
	        String enc = Base64.toBase64String(byteOs.toByteArray());
	        //System.out.println(enc);
	        fw.write("ssh-rsa ");
	        fw.write(enc);

	        fw.write(" "+alias+"\n");

	        fw.flush();
	        fw.close();
	        System.out.println(String.format("Exporting the %s to '%s'", "ssh public key", filename));
			
	        
		} catch(IOException ioe){
			ioe.printStackTrace();
		}
	}

	public static void exportKeyPair(KeyPair pair, String identity, String type, Date date)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {

		ConfigFile c = ConfigFile.getInstance();

		// See RFC4880
		PGPSignatureSubpacketVector unhashedPcks = null;
		PGPSignatureSubpacketGenerator svg = new PGPSignatureSubpacketGenerator();

		if(c.hasKey(type+".primaryUserId")){
			svg.setPrimaryUserID(c.getBoolean(type + ".primaryUserId.mandatory") , c.getBoolean(type + ".primaryUserId"));
		}
		if (c.hasKey(type +".feature")){
			svg.setFeature(c.getBoolean(type +".feature.mandatory"), c.getFeature(type + ".feature"));
		}
		if (c.hasKey(type +".keyExpirationTime")){
			svg.setKeyExpirationTime(c.getBoolean(type +".keyExpirationTime.mandatory"), c.getIntProperty(type + ".keyExpirationTime",86400 * 366 * 2));
		}
		if (c.hasKey(type +".trustSignature.value")){
			svg.setTrust(c.getBoolean(type +".trustSignature.mandatory"), c.getIntProperty(type+ ".trustSignature.depth",0),  c.getIntProperty(type+ ".trustSignature.value",3));
		}
		
		svg.setKeyFlags(c.getBoolean(type + ".keyFlags.mandatory"), c.getIntFromKeyFlags(type + ".keyFlags"));
		
		if (c.hasKey(type + ".prefs.encAlgs.mandatory")){
			if (c.getIntArray(type + ".prefs.encAlgs") != null) {
				svg.setPreferredSymmetricAlgorithms(c.getBoolean(type + ".prefs.encAlgs.mandatory"),
						c.getIntArray(type + ".prefs.encAlgs"));
			}
		}
		if (c.hasKey(type + ".prefs.hashAlgs.mandatory")){
			if (c.getIntArray(type + ".prefs.hashAlgs") != null) {
				svg.setPreferredHashAlgorithms(c.getBoolean(type + ".prefs.hashAlgs.mandatory"),
						c.getIntArray(type + ".prefs.hashAlgs"));
			}
		}
		if (c.hasKey(type + ".prefs.comprAlgs.mandatory")){
			if (c.getIntArray(type + ".prefs.comprAlgs") != null) {
				svg.setPreferredCompressionAlgorithms(c.getBoolean(type + ".prefs.comprAlgs.mandatory"),
						c.getIntArray(type + ".prefs.comprAlgs"));
			}
		}
		

		PGPSignatureSubpacketVector hashedPcks = svg.generate();

		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyPair keyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, pair, date);
		
		
		//PGPSecretKey secretKey = new PGPSecretKey(c.getCertification(type+ ".certification"), keyPair, identity, sha1Calc,
		//		hashedPcks, unhashedPcks, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(),
		//				HashAlgorithmTags.SHA512), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(pw.toCharArray()));
		
		PGPSecretKey secretKey = new PGPSecretKey(c.getCertification(type+ ".certification"), keyPair, identity, sha1Calc,
				hashedPcks, unhashedPcks, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(),
						HashAlgorithmTags.SHA512), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).build(pw.toCharArray()));
		
		exportKeyPair(secretKey);		
	}

	
	public static void exportKeyPair(PGPSecretKey keyPair){
		FileOutputStream out = null;
		try {
			//write public key
			fingerprint=ConversionUtil.ByteArrayToHexString(keyPair.getPublicKey().getFingerprint());
			String filename = fingerprint + "_pub.bpg";
			out = new FileOutputStream(filename);
			keyPair.getPublicKey().encode(out);
			out.close();
			System.out.println(String.format("Exporting %s to '%s'", "public key", filename));
			//write secret key
			filename = fingerprint + "_sec.bpg";
			out = new FileOutputStream(filename);
			keyPair.encode(out);
			System.out.println(String.format("Exporting %s to '%s'", "private key", filename));
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static String selectAlias(){
		String alias="User";
		if (certificate == null){
			return "User";
		}
		ArrayList<String> names = new ArrayList<String>();
		
		X509Certificate c = (X509Certificate) certificate;
		
		Principal principal=c.getSubjectDN();
		String dn=principal.getName();
		System.out.println("DN: "+dn);
		String[]dnparts=dn.split(",");
		String[]dnsubparts=dnparts[0].split("=");
		String dnname=dnsubparts[1];
		names.add(dnname);
		try {
			Collection<List<?>> an = c.getSubjectAlternativeNames();
			for (List l:an){
				//System.out.println("Subject alternative name:" +l.toString());
				for (int i=0; i<=an.size();i++){
					String na=l.get(i).toString();
					if (na.length()>2){
						names.add(l.get(i).toString());
					}
				}
			}
			
		} catch (CertificateParsingException e) {
			e.printStackTrace();
		}
		if (names.size()>1){
			
			Console console = System.console();
	        if (console == null) {
	            System.out.println("Couldn't get Console instance");
	            System.exit(0);
	        }
			System.out.println("Choose your alias name:");
			for (int i=0; i < names.size(); i++){
				System.out.println(String.format("%2d.) %s", i, names.get(i)));
			}
			int sel=-1;
			while (sel < 0 || sel >= names.size()){
				System.out.println(String.format("Please choose a number between %d and %d.",0 , names.size()-1));
				String inLine=console.readLine();
				try {
					sel=Integer.parseInt(inLine);
				}catch(Exception ex){
					System.err.println(String.format("Invalid input '%s'. Please try again.", inLine));
				}
			}
			return names.get(sel);
		}else if (names.size()==1){
			return names.get(0);
		}
		return alias;
	}
	
	public static void exportKeyRing(PGPKeyRingGenerator keyRingGen){
		FileOutputStream out = null;
		try {
			PGPPublicKeyRing pkr = keyRingGen.generatePublicKeyRing();
			PGPSecretKeyRing skr = keyRingGen.generateSecretKeyRing();
			fingerprint=ConversionUtil.ByteArrayToHexString(pkr.getPublicKey().getFingerprint());
			String filename = fingerprint + ".pkr";
			out = new FileOutputStream(filename);
			pkr.encode(out);
			out.close();
			System.out.println(String.format("Exporting %s to '%s'", "private key ring", filename));
			
			filename= fingerprint + ".skr";
			out = new FileOutputStream(filename);
			skr.encode(out);
			out.close();
			System.out.println(String.format("Exporting %s to '%s'", "public key ring", filename));
			
		} catch (FileNotFoundException e) {
			System.err.println("Failed writing key ring: " + e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.err.println("Failed writing key ring: " + e.getMessage());
			e.printStackTrace();
		}
	}
	
	public static KeyPair readKeyPair(String filename, String alias) throws Exception{
		KeyPair kp = null;
		Key key = null;
        Enumeration aliasEnum;
        
        
        //check if file exists
        File f = new File(filename);
        if(!f.exists() || f.isDirectory()) { 
            throw new Exception(String.format("File '%s' not found.",filename));
        }
        
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        

		KeyStore p12 = KeyStore.getInstance("pkcs12");
		
		int maxTries=3;
        int nTries=0;
        while (nTries < maxTries && key == null){
        	char passwordArray[] = console.readPassword(String.format("Enter password for '%s': ",filename));
            //char passwordArray[] = new char[]{ '0','0','0','0','0','0','0','0' };
        	pw=new String(passwordArray);
			try {
				p12.load(new FileInputStream(f), passwordArray);
				aliasEnum = p12.aliases();
				while(aliasEnum.hasMoreElements()){
					
		        	String keyName = (String)aliasEnum.nextElement();
		        	if ((alias != null) && !keyName.contains(alias)){ continue; }
		        	key = p12.getKey(keyName, passwordArray);
		        	certificate = p12.getCertificate(keyName);
		        	
		        	kp = new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
		        	return kp;
				}
			} catch (UnrecoverableKeyException e) {
				System.err.println("Failed to decrypt key. Try again.");
			}
        }
        throw new Exception(String.format("Failed to retrieve key from '%s'.",filename));
	}
	
	public static KeyPair readKeyPair(String filename, String password, String alias) throws Exception {
		KeyPair kp = null;
		Key key = null;
		Enumeration aliasEnum;

		// check if file exists
		File f = new File(filename);
        if(!f.exists() || f.isDirectory()) { 
            throw new Exception(String.format("File '%s' not found.",filename));
        }

		KeyStore p12 = KeyStore.getInstance("pkcs12");

		try {
			p12.load(new FileInputStream(f), password.toCharArray());
			aliasEnum = p12.aliases();
			while (aliasEnum.hasMoreElements()) {

				String keyName = (String) aliasEnum.nextElement();
				if ((alias != null) && !keyName.contains(alias)) {
					continue;
				}
				key = p12.getKey(keyName, password.toCharArray());
				certificate = p12.getCertificate(keyName);
				kp = new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
				return kp;
			}
		} catch (UnrecoverableKeyException e) {
			System.err.println("Failed to decrypt key.");
			System.exit(1);
		}
		throw new Exception(String.format("Failed to retrieve key from '%s'.", filename));
	}
	
	public static void generateKeyRingFromKeyPairs(KeyPair masterKey, KeyPair subKey, Date d, String id, String type)
			throws Exception {

		ConfigFile c = ConfigFile.getInstance();
		
		// bcpg 1.48 exposes this API that includes s2kcount. Earlier
		// versions use a default of 0x60.
		int s2kcount = c.getIntProperty("keyring.s2kcount",250);
		
		// This object generates individual key-pairs.
		PGPKeyPair masterKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, masterKey, d);

		// Then an encryption sub key.
		PGPKeyPair subKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, subKey, d);

		// Add a self-signature on the id
		PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();

		if(c.hasKey("mk.primaryUserId")){
			signhashgen.setPrimaryUserID(c.getBoolean("mk.primaryUserId.mandatory") , c.getBoolean("mk.primaryUserId"));
		}
		if (c.hasKey("mk.feature")){
			signhashgen.setFeature(c.getBoolean("mk.feature.mandatory"), c.getFeature("mk.feature"));
		}
		if (c.hasKey("mk.keyExpirationTime")){
			signhashgen.setKeyExpirationTime(c.getBoolean("mk.keyExpirationTime.mandatory"), c.getIntProperty("mk.keyExpirationTime",86400 * 366 * 2));
		}
		if (c.hasKey("mk.trustSignature.value")){
			signhashgen.setTrust(c.getBoolean("mk.trustSignature.mandatory"), c.getIntProperty("mk.trustSignature.depth",0),  c.getIntProperty("mk.trustSignature.value",3));
		}
		// Add signed meta data on the signature.
		// 1) Declare its purpose
		signhashgen.setKeyFlags(c.getBoolean("mk.keyFlags.mandatory"), c.getIntFromKeyFlags("mk.keyFlags"));
		// 2) Set preferences for secondary crypto algorithms to use
		// when sending messages to this key.
		if (c.hasKey("mk.prefs.encAlgs")){
			signhashgen.setPreferredSymmetricAlgorithms(c.getBoolean("mk.prefs.encAlgs.mandatory"), c.getIntArray("mk.prefs.encAlgs"));
		}
		if (c.hasKey("mk.prefs.hashAlgs")){
			signhashgen.setPreferredHashAlgorithms(c.getBoolean("mk.prefs.hashAlgs.mandatory"), c.getIntArray("mk.prefs.hashAlgs"));
		}
		if (c.hasKey("mk.prefs.comprAlgs")){
			signhashgen.setPreferredCompressionAlgorithms(c.getBoolean("mk.prefs.comprAlgs.mandatory"), c.getIntArray("mk.prefs.comprAlgs"));
		}
		// 3) Request senders add additional checksums to the
		// message (useful when verifying unsigned messages.)

		// Create a signature on the sub key.
		PGPSignatureSubpacketGenerator skhashgen = new PGPSignatureSubpacketGenerator();
		skhashgen.setKeyFlags(c.getBoolean(type +".keyFlags.mandatory"), c.getIntFromKeyFlags(type +".keyFlags"));
		if (c.hasKey(type+".primaryUserID")){
			skhashgen.setPrimaryUserID(c.getBoolean(type + ".getBoolean.mandatory"), c.getBoolean(type + ".getBoolean"));
		}
		if (c.hasKey(type +".trustSignature.value")){
			skhashgen.setTrust(c.getBoolean(type +".trustSignature.mandatory"), c.getIntProperty(type+ ".trustSignature.depth",0),  c.getIntProperty(type+ ".trustSignature.value",3));
		}
		if (c.hasKey(type+".keyExpirationTime")){
			skhashgen.setKeyExpirationTime(c.getBoolean(type +".keyExpirationTime.mandatory"), c.getIntProperty(type+".keyExpirationTime",86400 * 366 * 2));
		}
		if (c.hasKey(type +".feature")){
			skhashgen.setFeature(c.getBoolean(type +".feature.mandatory"), c.getFeature(type + ".feature"));
		}
		if (c.hasKey(type+".prefs.encAlgs")){
			skhashgen.setPreferredSymmetricAlgorithms(c.getBoolean(type+".prefs.encAlgs.mandatory"), c.getIntArray(type+".prefs.encAlgs"));
		}
		if (c.hasKey(type+".prefs.hashAlgs")){
			skhashgen.setPreferredHashAlgorithms(c.getBoolean(type+".prefs.hashAlgs.mandatory"), c.getIntArray(type + ".prefs.hashAlgs"));
		}
		if (c.hasKey(type+".prefs.comprAlgs")){
			skhashgen.setPreferredCompressionAlgorithms(c.getBoolean(type+".prefs.comprAlgs.mandatory"), c.getIntArray(type + ".prefs.comprAlgs"));
		}

		// Objects used to encrypt the secret key.
		PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
		PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

		//Encryptor for the private keys
		PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc,
				s2kcount)).build(pw.toCharArray());

		// Finally, create the keyring itself. The constructor
		// takes parameters that allow it to generate the self
		// signature.
		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(c.getCertification("mk.certification"), masterKeyPair, id,
				sha1Calc, signhashgen.generate(), null,
				new BcPGPContentSignerBuilder(masterKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
				pske);

		// Add our encryption sub key, together with its signature.
		keyRingGen.addSubKey(subKeyPair, skhashgen.generate(), null);

		
		exportKeyRing(keyRingGen);
	}
}