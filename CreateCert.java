import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;


public class CreateCert
{

    public static String priKeyPath;
    

    public CreateCert(String priKeyPath, String certificatePath)
    {
    	this.priKeyPath = priKeyPath;
    	
    	/**
         * 
         * initializes keytool to obtain java key store file,
         * private key and self-signed certificate
         * 
         */
        KeytoolStarter keytoolStarter = new KeytoolStarter();
        keytoolStarter.start(certificatePath);

    }


    public static void encodePriKeyFile(String password) throws IOException, InvalidKeyException,
    InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
    BadPaddingException
	{
		BufferedReader br = new BufferedReader(new FileReader(priKeyPath));
		// read private key file
		String line = "";
		StringBuilder priKey = new StringBuilder();
		while((line = br.readLine()) != null)
		    priKey.append(line);
		
		br.close();
		String priKeyStr = priKey.toString();
		// encode the private key with specified password
		String encoded = encode(priKeyStr, password);
		
		BufferedWriter bw = new BufferedWriter(new FileWriter(priKeyPath));
		
		bw.write(encoded);
		
		bw.close();
	}
	
	private static String encode(String text, String password)
	    throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	    IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
	// transform password to char array to use in encryption
		char[] ch = password.toCharArray(); 
		
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(ch, CreateCert.salt, 32768, 128);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		
		// encrypt private key file with hash result of password
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		
		byte[] ciphertext = cipher.doFinal(text.getBytes("UTF-8"));
		
		String encodedText = new String(Base64.getEncoder().encode(ciphertext));
		return encodedText;
	}
	
	public static void decodePriKeyFile(String priKeyPath, String password) throws IOException, InvalidKeyException,
	    InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
	    BadPaddingException
	{
		BufferedReader br = new BufferedReader(new FileReader(priKeyPath));
		// read file
		StringBuilder x = new StringBuilder();
		String line = "";
		while((line = br.readLine())!= null)
		    x.append(line);
		String y = x.toString();
		br.close();
		
		// decode the private key file with specified password
		String decoded = decode(y, password);
		
		BufferedWriter bw = new BufferedWriter(new FileWriter(priKeyPath));
		bw.write(decoded);
		bw.close();
	}
	
	
	private static String decode(String text, String password)
	    throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	    IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
	{
	// transform password to char array to use in encryption
		char[] ch = password.toCharArray(); 
		
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(ch, CreateCert.salt, 32768, 128);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		
		// encrypt private key file with hash result of password
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret);
		byte[] decoded = Base64.getDecoder().decode(text.getBytes("UTF-8"));
		byte[] plainbyte = cipher.doFinal(decoded);
		String last = new String(plainbyte, "UTF-8");
		return last;
	}
	public static final byte[] salt = {-98, -24, 122, -27, -106, -97, -4, -15};
		
	public static String hashPassword(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException
	{
		
		// binary representation of password to pad
		String binary = new BigInteger(password.getBytes()).toString(2);
		
		/**
		 * pads string with "01" sequence
		 */
		StringBuilder pad = new StringBuilder(binary);
		
		for (int i= 0; i < (512-password.length()*8)/2; i++)
		    pad.append("01");
		
		// resulting string to be hashed
		String paddedBin = pad.toString();
		
		String x = new String(new BigInteger(paddedBin, 2).toByteArray());
		
		// create message digest with mode MD5
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(x.getBytes());
		byte[] digest = md.digest();
		String hashedValue = new BigInteger(digest).toString(2);
		
		return hashedValue;
	}
	
	public static void priKeyFileGenerator() throws IOException
	{
		BufferedReader bf = new BufferedReader(new FileReader("key.pem"));
		// creates new private key file with the path given
		FileWriter newFile = new FileWriter(priKeyPath);
		BufferedWriter bw = new BufferedWriter(new FileWriter(priKeyPath));
		String line = "";
		String controlLine = "This is a private key file";
		StringBuilder sb = new StringBuilder();
		boolean started = false;
		while((line = bf.readLine()) != null)
		{
		    if (started)
		        sb.append(line);
		    if (line.equals("-----BEGIN PRIVATE KEY-----"))
		        started = true;
		}
		String out = sb.toString();
		String last = out
		.replace("-----BEGIN PRIVATE KEY-----", "")
		.replaceAll(System.lineSeparator(), "")
		.replace("-----END PRIVATE KEY-----", "");
		StringBuilder sb2 = new StringBuilder(last);
		sb2.append(controlLine);
		bw.write(sb2.toString());
		
		bf.close();
		bw.close();
	}
	
	
	public static PublicKey getPublicKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		FileInputStream is = new FileInputStream("ichecker.jks");
		
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, "111111".toCharArray());
		
		String alias = "ichecker";
		PublicKey publicKey = null;
		Key key = keystore.getKey(alias, "111111".toCharArray());
		if (key instanceof PrivateKey)
		{
		  // get certificate of public key
		  java.security.cert.Certificate cert = keystore.getCertificate(alias);
		
		  // get public key
		  publicKey = cert.getPublicKey();
		
		}
		
		return publicKey;
		
	}
	
	public static PrivateKey getPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException
	{
		FileInputStream is = new FileInputStream("ichecker.jks");
		
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, "111111".toCharArray());
		
		String alias = "ichecker";
		PrivateKey privateKey = null;
		Key key = keystore.getKey(alias, "111111".toCharArray());
		if (key instanceof PrivateKey)
		{
		  // get certificate of public key
		  Certificate cert = keystore.getCertificate(alias); 
		  privateKey = (PrivateKey) key;
		  
		}
		
		return privateKey;
	
	}

}
