package org.bfe.gpg.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPSignature;

public class ConfigFile {
	static ConfigFile instance = null;
	private Properties config=null;
	public String filename = null;
	public static final String bcClassPath="org.bouncycastle.bcpg.";
	public static final String openPgpClassPath="org.bouncycastle.openpgp.";
	public static final String defaultConfigFile="KeySettings.properties";
	
	private ConfigFile(String filename){
		this.filename=filename;
		config = new Properties();
		loadData();
		instance=this;
	}
	
	private ConfigFile(){
		this.filename=defaultConfigFile;
		config = new Properties();
		loadDefault();
		instance=this;
	}
	
	public void loadDefault() {
		try{
			InputStream is = ConfigFile.class.getResourceAsStream(defaultConfigFile);
			config.load(is);
			
		}catch(Exception ex){
			System.err.println(String.format("Failed loading config %s from the jar archive: ", filename, ex.getMessage()));
			System.exit(1);
		}
	}
	
	public void loadData(){
		try{
			File file = new File(filename);
			InputStream is = new FileInputStream(file);
			config.load(is);
		}catch(Exception e){
			System.err.println(String.format("Failed loading '%s': %s", filename, e.getMessage()));
			if (!filename.contentEquals(defaultConfigFile)){
				filename=defaultConfigFile;
				loadData();
			}
		}
	}
	
	public static ConfigFile getInstance(){
		if (instance == null){
			new ConfigFile();
		}
		return instance;
	}
	
	public static ConfigFile getInstance(String filename){
		if (instance == null){
			new ConfigFile(filename);
		}
		if (!instance.filename.contentEquals(filename)){
			instance.filename=filename;
			instance.loadData();
		}
		return instance;
	}
	
	public String[] getProperties(String key){
		String val= config.getProperty(key);
		if (val == null){return null;}
		String[] result = val.split(",");
		for (int i = 0; i < result.length; i++){
			result[i]=result[i].trim();
		}
		return result;
	}
	
	public int[] getIntArray(String key){
		String val= config.getProperty(key);
		ArrayList<Integer> ret = new ArrayList<Integer>();
		if (val == null){
			System.err.println(String.format("Property '%s' not found in %s. Defaulting to 0.",key,filename));
			return new int[0];
		}
		String[] result = val.split(",");
		for (int i = 0; i < result.length; i++){
			result[i]=result[i].trim();
			String[] vals = result[i].split("\\.");
			try {
				Class myClass = Class.forName(bcClassPath + vals[0]);
				Field myField = myClass.getDeclaredField(vals[1]);
				ret.add(myField.getInt(null));
			} catch (ClassNotFoundException e) {
				System.err.println(String.format("Failed to find class for '%s': %s",result[i],e.getMessage()));
			} catch (NoSuchFieldException e) {
				System.err.println(String.format("Failed to find field for '%s': %s",result[i],e.getMessage()));
			} catch (SecurityException e) {
				System.err.println(String.format("Failed to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalArgumentException e) {
				System.err.println(String.format("Illegal arg to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalAccessException e) {
				System.err.println(String.format("Illegal access field for '%s': %s",result[i],e.getMessage()));
			}
			
		}
		int[] r = new int[ret.size()];
		for (int i =0; i< ret.size(); i++){
			r[i]=ret.get(i);
		}
		return r;
	}
	
	public Integer getIntFromKeyFlags(String key){
		String val= config.getProperty(key);
		Integer ret = 0;
		if (val == null){
			System.err.println(String.format("Property '%s' not found in %s. Defaulting to set all.",key,filename));
			return KeyFlags.AUTHENTICATION | KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
		}
		String[] result = val.split(",");
		for (int i = 0; i < result.length; i++){
			result[i]=result[i].trim();
			String[] vals = result[i].split("\\.");
			try {
				Class myClass = Class.forName(bcClassPath + "sig."+ vals[0]);
				Field myField = myClass.getDeclaredField(vals[1]);
				ret |= myField.getInt(null);
			} catch (ClassNotFoundException e) {
				System.err.println(String.format("Failed to find class for '%s': %s",result[i],e.getMessage()));
			} catch (NoSuchFieldException e) {
				System.err.println(String.format("Failed to find field for '%s': %s",result[i],e.getMessage()));
			} catch (SecurityException e) {
				System.err.println(String.format("Failed to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalArgumentException e) {
				System.err.println(String.format("Illegal arg to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalAccessException e) {
				System.err.println(String.format("Illegal access field for '%s': %s",result[i],e.getMessage()));
			}
			
		}
		return ret;
	}
	
	
	
	public Integer getIntFromObject(String key, String className){
		String val= config.getProperty(key);
		Integer ret = 0;
		if (val == null){return null;}
		String[] result = val.split(",");
		for (int i = 0; i < result.length; i++){
			result[i]=result[i].trim();
			String[] vals = result[i].split("\\.");
			Class myClass=null;
			try {
				myClass = Class.forName( className + vals[0]);
				
				Field myField = myClass.getDeclaredField(vals[1]);
				ret |= myField.getInt(null);
			} catch (ClassNotFoundException e) {
				System.err.println(String.format("Failed to find class for '%s': %s",result[i],e.getMessage()));
			} catch (NoSuchFieldException e) {
				System.err.println(String.format("Failed to find field for '%s': %s",result[i],e.getMessage()));
				Field[] df = myClass.getDeclaredFields();
				System.err.println("Possible fields are:");
				for (Field f: df){
					System.err.println(" - " +f.getName());
				}
			} catch (SecurityException e) {
				System.err.println(String.format("Failed to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalArgumentException e) {
				System.err.println(String.format("Illegal arg to access field for '%s': %s",result[i],e.getMessage()));
			} catch (IllegalAccessException e) {
				System.err.println(String.format("Illegal access field for '%s': %s",result[i],e.getMessage()));
			}
		}
		return ret;
	}
	
	public Byte getFeature(String key){
		String val= config.getProperty(key);
		Byte ret = null;
		if (val == null){return null;}
		String[] vals =val.split("\\.");
		try {
			Class myClass = Class.forName(bcClassPath + "sig."+ vals[0]);
			Field myField = myClass.getDeclaredField(vals[1]);
			ret = myField.getByte(null);
		} catch (ClassNotFoundException e) {
			System.err.println(String.format("Failed to find class for '%s': %s",val,e.getMessage()));
		} catch (NoSuchFieldException e) {
			System.err.println(String.format("Failed to find field for '%s': %s",val,e.getMessage()));
		} catch (SecurityException e) {
			System.err.println(String.format("Failed to access field for '%s': %s",val,e.getMessage()));
		} catch (IllegalArgumentException e) {
			System.err.println(String.format("Illegal arg to access field for '%s': %s",val,e.getMessage()));
		} catch (IllegalAccessException e) {
			System.err.println(String.format("Illegal access field for '%s': %s",val,e.getMessage()));
		}
		return ret;
	}
	
	public String getProperty(String key){
		return config.getProperty(key);
	}
	
	public Integer getIntProperty(String key, int defaultVal){
		Integer i;
		try {
			i = Integer.parseInt(config.getProperty(key));
			return i;
		}catch(Exception e){
			System.err.println(String.format("Failed reading '%s': %s",key,e.getMessage()));
			System.err.println(String.format("Defaulting to '%d'",defaultVal));
			return defaultVal;
		}
	}
	
	public boolean hasKey(String key){
		String val = config.getProperty(key);
		if (val!=null){
			return true;
		}
		return false;
	}
	
	public boolean getBoolean(String key){
		String val = config.getProperty(key);
		if (val == null){
			System.err.println(String.format("Property '%s' not found in %s. Defaulting to 'false'.",key,filename));
			return false;
		}
		if (val.matches("^[Tt]")){
			return true;
		}
		return false;
	}
	
	public int getCertification(String key){
		String val = config.getProperty(key);
		if (val == null){
			System.err.println(String.format("Property '%s' not found in %s. Defaulting to 'PGPSignature.POSITIVE_CERTIFICATION'.",key,filename));
			return PGPSignature.DEFAULT_CERTIFICATION;
		}
		return getIntFromObject(key, openPgpClassPath);
	}
	
}
