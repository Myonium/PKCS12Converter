package org.bfe.gpg.utils;


public class ConversionUtil {
	
	public static int ByteToUnsignedInt(byte b) {
	    return b & 0xFF;
	 }
	/**
	 * Converts an ASCII string to a byte array representation.
	 * 
	 * @param strASCII the string to convert
	 */
	public static byte[] AscStringToByteArray(String strAscii) {
		byte[] bytKey = new byte[strAscii.length()];

		for (int x = 0; x < bytKey.length; x++) {
			bytKey[x] = (byte) strAscii.charAt(x);
		}
		return bytKey;
	}

	public static int[] AscStringToIntArray(String strAscii) {
		int[] intKey = new int[strAscii.length()];

		for (int x = 0; x < intKey.length; x++) {
			intKey[x] = (int) strAscii.charAt(x);
		}
		return intKey;
	}
	

	
    public static int byteArrayToInt(byte[] byteArray) {
        return byteArrayToInt(byteArray, 0, byteArray.length);
    }
    
    public static int byteArrayToInt(byte[] byteArray, int startPos, int length) {
        if (byteArray == null) {
            throw new IllegalArgumentException("Parameter 'byteArray' cannot be null");
        }
        if (length <= 0 || length > 4) {
            throw new IllegalArgumentException("Length must be between 1 and 4. Length = " + length);
        }
        int value = 0;
        for (int i = startPos; i < length; i++) {
            value += ((byteArray[i] & 0xFF) << 8 * (byteArray.length - i - 1));
        }
        return value;
    }
    
	/**
	 * Converts a byte array to a ASCII string representation.
	 * 
	 * @param byteArray the array to convert
	 */

	public static String ByteArrayToAscString(byte[] byteArray) {
		String strAscii = new String();
		strAscii = "";

		int int_lu;
		char c;

		for (int i = 0; i < byteArray.length; i++) {
			int_lu = ((int) byteArray[i] & 0x000000ff);
			c = (char) int_lu;
			strAscii = strAscii + String.valueOf(c);
		}
		return strAscii;
	}

	/**
	 * Converts a byte to a hex string representation.
	 * 
	 * @param byte to String convert
	 */
	
	public static String ByteToHexString(byte tbyte) {
		int b = ((int) tbyte & 0x000000ff);
		if (b < 16) {
			return "0" + Integer.toHexString(b).toUpperCase();
		} else {
			return Integer.toHexString(b).toUpperCase();
		}

	}
	
	/**
	 * Converts a byte array to a hex string representation.
	 * 
	 * @param byteArray the array to convert
	 */

	public static String ByteArrayToHexString(byte[] byteArray) {
		String strArray = "";

		for (int x = 0; x < byteArray.length; x++) {
			strArray = strArray + ByteToHexString(byteArray[x]);
		}
		return strArray;
	}
	

    public static String ByteArrayToHexFormattedString(String in, int indent, boolean wrapLines) {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            buf.append(c);

            int nextPos = i+1;
            if (wrapLines && nextPos % 32 == 0 && nextPos != in.length()) {
                buf.append("\n").append(stringRepeater(" ",indent));
            } else if (nextPos % 2 == 0 && nextPos != in.length()) {
                buf.append(" ");
            }
        }
        return buf.toString();
    }
    
    public static String ByteArrayToHexFormattedString(byte[] data, int indent){
    	return ByteArrayToHexFormattedString(byteArrayToHexString(data), indent, true);
    }
    
    public static String ByteArrayToHexFormattedStringNoWrap(byte[] data) {
    	return ByteArrayToHexFormattedString(byteArrayToHexString(data), 0, false);
    }

    public static String ByteArrayToHexFormattedString(byte[] data) {
        return ByteArrayToHexFormattedString(byteArrayToHexString(data), 0, true);
    }
    
    /**
     * Converts a byte array into a hex string.
     * @param byteArray the byte array source
     * @return a hex string representing the byte array
     */
    public static String byteArrayToHexString(final byte[] byteArray) {
        if (byteArray == null) {
            //return "" instead?
            throw new IllegalArgumentException("Argument 'byteArray' cannot be null");
        }
        int readBytes = byteArray.length;
        StringBuilder hexData = new StringBuilder();
        int onebyte;
        for (int i = 0; i < readBytes; i++) {
            onebyte = ((0x000000ff & byteArray[i]) | 0xffffff00);
            hexData.append(Integer.toHexString(onebyte).substring(6));
        }
        return hexData.toString();
    }

	public static int[] ByteArrayToIntArray(byte[] byteArray) {
		int[] out = new int[byteArray.length];
		for (int i = 0; i < byteArray.length; i++) {
			out[i] = ((int) byteArray[i] & 0x000000ff);
		}
		return out;
	}

	public static short[] ByteArrayToShort(byte[] byteArray) {
		short[] out = new short[byteArray.length];
		for (int i = 0; i < byteArray.length; i++) {
			out[i] = (short) byteArray[i];
		}
		return out;
	}

	/**
	 * Converts a byte array to a spaced string representation.
	 * 
	 * @param byteArray the array to convert
	 */

	public static String ByteArrayToSpacedHexString(byte[] byteArray) {
		String strArray = new String();
		strArray = "";

		for (int x = 0; x < byteArray.length; x++) {
			int b = ((int) byteArray[x] & 0x000000ff);
			if (b < 16) {
				strArray = strArray + "0" + Integer.toHexString(b).toUpperCase() + " ";
			} else {
				strArray = strArray + Integer.toHexString(b).toUpperCase() + " ";
			}
		}
		return strArray;
	}


	/**
	 * Converts a byte pair to a short.
	 * 
	 * @param msb most significant byte
	 * @param lsb least significant byte
	 */
	public static short BytePairToShort(byte msb, byte lsb) {
		short smsb, slsb;
		smsb = (short) ((msb & 0x00FF) << 8);
		slsb = (short) (lsb & 0x00FF);
		short res = (short) (smsb | slsb);
		return res;
	}

	

	/**
	 * Converts a hex string to a byte array representation.
	 * 
	 * @param strHex the string to convert
	 */
	public static byte[] HexStringToByteArray(String in) {
		String strHex=in.replaceAll("[\\s\\n\\r]", "");   //remove spaces, returns, new lines ....
		byte[] bytKey = new byte[(strHex.length() / 2)];
		int y = 0;
		String strbyte;

		for (int x = 0; x < bytKey.length; x++) {
			strbyte = strHex.substring(y, (y + 2));
			if (strbyte.equals("FF")) {
				bytKey[x] = (byte) 0xFF;
			} else {
				try {
					bytKey[x] = (byte) Integer.parseInt(strbyte, 16);
				} catch (NumberFormatException e) {
					System.err.println("HexStringToByteArray failed for " + strbyte + " in " + strHex);
					//System.exit(1);
				}
			}
			y = y + 2;
		}
		return bytKey;
	}

	public static int hexStringToInt(String in) {
		if (in.equals("FF")) {
			return (int) 0xFF;
		} else {
			try {
				return (int) Integer.parseInt(in, 16);
			} catch (NumberFormatException e) {
				System.err.println( "HexStringToInt failed for: " + e.toString());
			}
		}
		return 0;
	}

	public static int[] hexStringToIntArray(String strHex) {
		int intKey[] = new int[(strHex.length() / 2)];
		int y = 0;
		String strInt;

		for (int x = 0; x < intKey.length; x++) {
			strInt = strHex.substring(y, (y + 2));
			if (strInt.equals("FF")) {
				intKey[x] = (int) 0xFF;
			} else {
				try {
					intKey[x] = (int) Integer.parseInt(strInt, 16);
				} catch (NumberFormatException e) {
					System.err.println( "HexStringToIntArray failed for " + e.toString());
				}
			}

			y = y + 2;
		}

		return intKey;
	}

	
	/**
	 * Converts an int into a 2 byte array.
	 * 
	 * @param i integer to convert
	 */
	public static byte[] IntToBytePair(int i) {
		byte[] retVal = new byte[2];
		retVal[0] = (byte) ((i & 0xFFFF) >> 8);
		retVal[1] = (byte) (i & 0x00FF);
		return retVal;
	}


	/**
		 * Converts an int array into hexString
		 * 
		 * @param i integer to convert
		 */
	public static String IntToHexString(int b) {
		// with space at the end!
		String strArray = new String();
		strArray = "";

		if (b < 16) {
			strArray = strArray + "0" + Integer.toHexString(b).toUpperCase() + " ";
		} else {
			strArray = strArray + Integer.toHexString(b).toUpperCase() + " ";
		}
		return strArray;
	}



	
	/**
	 * Converts an long into a 4 byte array.
	 * 
	 * @param i integer to convert
	 */
	public static byte[] LongToByteArray(long i) {
		byte[] retVal = new byte[4];
		retVal[0] = (byte) ((i & 0xFFFFFFFF) >> 24);
		retVal[1] = (byte) ((i & 0x00FFFFFF) >> 16);
		retVal[0] = (byte) ((i & 0x0000FFFF) >> 8);
		retVal[1] = (byte) (i & 0x000000FF);
		return retVal;
	}
	

	/**
	 * Converts a short into a 2 byte array
	 * 
	 * @param i short to convert
	 */
	public static byte[] ShortToBytePair(short i) {
		byte[] retVal = new byte[2];
		retVal[0] = (byte) ((i & 0xFFFF) >> 8);
		retVal[1] = (byte) (i & 0x00FF);
		return retVal;
	}
	
	static public String stringRepeater(String str, int factor){
		StringBuilder out = new StringBuilder();
		
		for(int i = 0; i < factor; i++){
			out.append(str);
		}
		return out.toString();
	}
	
 
}
