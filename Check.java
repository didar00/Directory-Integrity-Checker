import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Check
{
	String regFilePath;
	String priKeyPath;
	String folderPath;
	String hashMode;
	
	public Check(String regPath, String priKeyPath, String folderPath, String hashMode)
	{
		regFilePath = regPath;
		this.priKeyPath = priKeyPath;
		this.folderPath = folderPath;
		this.hashMode = hashMode;
	}

	public void signatureVerification() throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		// gets public key
		PublicKey publicKey = CreateCert.getPublicKey();
		
		// gets the signature
		byte[] signature = FileOperations.getSignature();
		
		
		// decrypts the signature at the end of the registry file
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] decryptedMessageHash = cipher.doFinal(signature);
		
		String regContent = FileOperations.getContent();
		String hashedContent = CreateReg.getHash(regContent, hashMode);
		// convert hashed message to byte array in order to compare with signature hash value
		byte[] hashedContentByte = new BigInteger(hashedContent, 2).toByteArray();
		
		// compares two hash values
        boolean verified = Arrays.equals(decryptedMessageHash, hashedContentByte);
    
        
        if (verified)
        {
        	controlChanges();
        }
        else
        {
        	 String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
        	 String event = timestamp + ": Registry file verification failed!\n";
        	 FileOperations.updateLogFile(event);
        	 System.exit(0);
        }
	}
	
	


	
	
	private void controlChanges() throws NoSuchAlgorithmException, IOException
	{
		HashMap<String, String> fileMap = get_File_and_Hashes();
		File folder = new File(folderPath);
        File[] files = folder.listFiles();
        boolean noChange = true;
        

        for (File file : files)
        {
        	
            if (file.isFile())
            {
                // gets absolute path of the file
                String filePath = file.getAbsolutePath();
                // gets the content of the file
                String content = FileOperations.getContent(filePath);
                // calculates the hash value of file
                String hashValue = CreateReg.getHash(content, hashMode);

              
                /**
            	 *  if this particular file still exists,
            	 *  checks the state of the file
            	 */
                if (fileMap.containsKey(filePath))
                {
                	String otherHashValue = fileMap.get(filePath);
                	
                	/**
                	 *  Hash values of the same files are different,
                	 *  so the file has been altered
                	 */
                	if (!hashValue.equals(otherHashValue))
                	{
                		noChange = false;

                		String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                        StringBuilder event = new StringBuilder(timestamp);
                        event.append(": ").append(filePath).append(" is altered\n");
                        FileOperations. updateLogFile(event.toString()); 
                	}
                	fileMap.remove(filePath);
                }
                /**
            	 *  file does not exist,
            	 *  updates log file
            	 */
                else
                {
                	noChange = false;
                	String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                    StringBuilder event = new StringBuilder(timestamp);
                    event.append(": ").append(filePath).append(" is created\n");
                    FileOperations. updateLogFile(event.toString()); 
                    fileMap.remove(filePath);
                }
                
                
            }
        }
        
        /**
         *  there is no unchecked file
         */
        if (fileMap.isEmpty())
        {
        	if (noChange)
        	{
        		String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                StringBuilder event = new StringBuilder(timestamp);
                event.append(": ").append("The directory is checked and no change is detected!\n");
                FileOperations. updateLogFile(event.toString()); 
        	}
        }
        else
        {
        	for (String key : fileMap.keySet())
        	{
        		String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                StringBuilder event = new StringBuilder(timestamp);
                event.append(": ").append(key).append(" is deleted\n");
                FileOperations. updateLogFile(event.toString()); 
        	}
        }
	}
	
	public HashMap<String, String> get_File_and_Hashes() throws IOException
	{
		HashMap<String, String> fileMap = new HashMap<String, String>();
		int lineCount = FileOperations.getRegFileSize();
		BufferedReader br = new BufferedReader(new FileReader(regFilePath));
        String line = null;
        
        while((line = br.readLine()) != null)
        {
        	if (lineCount == 0)
        		break;
    		String[] tokens = line.split(" ");
        	fileMap.put(tokens[0], tokens[1]);
        	
        	lineCount--;
        }

        br.close();
        return fileMap;
	}
	
	

	
	
}
