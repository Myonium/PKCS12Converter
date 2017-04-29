
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.bfe.gpg.utils.ConfigFile;
import org.bfe.gpg.utils.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class PKCS12Converter {

	public static Options options = new Options();
	public static ConfigFile c=null;
	static{
		Option help = new Option( "h","help", false, "print this message" );
		options.addOption(help);
		Option in = Option.builder("i")
				.required(true)
                .hasArg()
                .longOpt("in")
                .desc(  "pkcs12 file to convert" )
                .build();
		options.addOption(in);
		Option date = Option.builder("d")
				.required(false)
                .hasArg()
                .longOpt("date")
                .desc(  "date in format 'yyyy-MM-dd HH:mm:ss' used for the key fingerprint" )
                .build();
		options.addOption(date);
		Option type = Option.builder("t")
				.required(true)
                .hasArg()
                .longOpt("type")
                .desc(  "must be oneo of 'sig(ning)', 'auth(entication)' or 'enc(ryption)'. The type specifies which key template is been used for the signatures (see KeySettings.properties)" )
                .build();
		options.addOption(type);
		Option masterkey = Option.builder("m")
				.required(false)
                .hasArg()
                .longOpt("masterkey")
                .desc(  "pkcs12 file containing the master key pair for signing the sub key" )
                .build();
		options.addOption(masterkey);
		Option config = Option.builder("c")
				.required(false)
                .hasArg()
                .longOpt("config")
                .desc( "configuration file containing the signature properites." )
                .build();
		options.addOption(config);
		/*
		Option alias = Option.builder("a")
				.required(false)
                .hasArg()
                .longOpt("alias")
                .desc(  "alias for the key in the pkcs12. Used only if you have multiple keypairs in the pkcs12." )
                .build();
		options.addOption(alias);
		Option ma = Option.builder("b")
				.required(false)
                .hasArg()
                .longOpt("master-alias")
                .desc(  "alias for the key in the master-pkcs12. Used only if you have multiple keypairs in the pkcs12." )
                .build();
		options.addOption(ma);
		*/
		Option uid = Option.builder("u")
				.required(false)
				.hasArg()
                .longOpt("uid")
                .desc(  "User ID of the key owner. Norally this is the full name and the eamil address." )
                .build();
		options.addOption(uid);
		Option ssh = Option.builder("s")
				.required(false)
                .longOpt("ssh")
                .desc(  "Export the ssh-public-key-file to add to the authorized_keys file." )
                .build();
		options.addOption(ssh);


	}

	public static SimpleDateFormat df= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	
	public static void usage(String error){
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp( "PKCS12Converter", options );
		
		System.out.println();
		System.out.println(String.format("Sample for converting a PKCS12 into a public / secret PGP key pair:"));
		System.out.println(String.format("java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --type authentication --in auth.p12"));
		System.out.println();
		System.out.println(String.format("Sample for a key ring with sub key:"));
		System.out.println(String.format("java -jar PKCS12Converter.jar --date '2017-04-24 22:00:00' --masterkey master.p12 --type auth --in auth.p12 --uid Dagobert"));
		
		if (error.length()>1){
			System.err.println(String.format("Error: %s",error));	
		}
		System.exit(-1);
	}
	
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd=null;

		try {
			cmd = parser.parse( options, args);
		} catch (org.apache.commons.cli.ParseException e2) {
			usage(e2.getMessage());
		}
		if (cmd.hasOption("help")){usage("");}
		
		String masterAlias = null;
		String alias=null;		
		String in = cmd.getOptionValue("in");
		String uid = cmd.getOptionValue("uid");
		String type = cmd.getOptionValue("type");
		String config = cmd.getOptionValue("config");
		KeyPair skp=null;
		String masterkey = cmd.getOptionValue("masterkey");
		KeyPair mkp=null;
		String date = cmd.getOptionValue("date");
		Boolean sshExport = cmd.hasOption("ssh");
		Date d=null;
		System.out.println(String.format("%20s : %s", "config",config));
		System.out.println(String.format("%20s : %s", "pkcs12",in));
		System.out.println(String.format("%20s : %s", "master pkcs12",masterkey));
		System.out.println(String.format("%20s : %s", "date",date));
		System.out.println(String.format("%20s : %s", "type",type));
		System.out.println(String.format("%20s : %s", "uid",uid));
		
		// Check if config is available ...
		if (config != null){
			c = ConfigFile.getInstance(config);
		}else{
			c = ConfigFile.getInstance();
		}
		if (c==null){
			usage("No configuration file found. The jar file should contain a 'org.bfe.utils.KeySettings.properties'.");
		}
		
		//Check parameters
		// Check type
		if (type.matches(("(?i)sig.*"))){
			type="sk";
		} else if (type.matches("(?i)auth.*")){
			type="ak";
		} else if (type.matches("(?i)enc.*")){
			type="ek";
		}else {
			usage(String.format("Illegal type '%s'. Type must be one of 'sig', 'enc', 'auth'.",type));
		}
		
		try {
			if (date !=null){
				d = df.parse(date);
			}else{
				d=new Date();
			}
		} catch (ParseException e1) {
			usage("Date must be formatted as 'yyyy-MM-dd HH:mm:ss': "+ e1.getMessage());
		}
		
		try {
			if (masterkey !=null){
				mkp=Utils.readKeyPair(masterkey, masterAlias);
			}
			skp=Utils.readKeyPair(in, alias);
			
		} catch (Exception e2) {
			usage(e2.getMessage());
		}
		
		if (uid == null){
			uid=Utils.selectAlias();
		}
		
		try {
			if (mkp == null){
				Utils.exportKeyPair(skp, uid, type, d);
			}else{
				Utils.generateKeyRingFromKeyPairs(mkp, skp, d, uid, type);
			}
			if (sshExport){
				Utils.exportSshKey(uid);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
