import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

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

	public void signatureVerification() throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException
	{
		Signature signature = null;
		PublicKey publicKey = CreateCert.getPublicKey();
		
        if (hashMode.equals("MD5"))
        	signature = Signature.getInstance("MD5withRSA");
        else if (hashMode.equals("SHA-256"))
        	signature = Signature.getInstance("SHA256withRSA");
        
        signature.initVerify(publicKey);
        byte[] messageBytes = getSignature();

        signature.update(messageBytes);

        boolean verified = signature.verify(messageBytes);
        
        if (verified)
        {
        	controlChanges();
        }
        else
        {
        	 String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
        	 String event = timestamp + ": Registry file verification failed!";
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
                    String otherFileContent = FileOperations.getContent(filePath);
                	String otherHashValue = CreateReg.getHash(otherFileContent, hashMode);
                	
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
                	String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                    StringBuilder event = new StringBuilder(timestamp);
                    event.append(": ").append(filePath).append(" is deleted\n");
                    FileOperations. updateLogFile(event.toString()); 
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
                        event.append(": ").append(" The directory is checked and no change is detected!\n");
                        FileOperations. updateLogFile(event.toString()); 
                	}
                }
                else
                {
                	for (String key : fileMap.keySet())
                	{
                		String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                        StringBuilder event = new StringBuilder(timestamp);
                        event.append(": ").append(key).append(" is created\n");
                        FileOperations. updateLogFile(event.toString()); 
                	}
                }
                
            }
        }
	}
	
	public HashMap<String, String> get_File_and_Hashes() throws IOException
	{
		HashMap<String, String> fileMap = new HashMap<String, String>();
		
		BufferedReader br = new BufferedReader(new FileReader(regFilePath));
        String line, temp;
        line = temp = null;
        
        while((line = br.readLine()) != null)
        {
        	temp = line;
        	if ((line = br.readLine()) != null)
        	{
        		String[] tokens = temp.split(" ");
            	fileMap.put(tokens[0], tokens[1]);
        	}
        	
        }
        
        br.close();
        return fileMap;
	}

    /**
    *  reads registry file
    *  @return signature
     * @throws IOException 
    */
    private byte[] getSignature() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader(regFilePath));
        String line = null;
        String signature = null;
        
        while((line = br.readLine()) != null)
        {
        	if ((line = br.readLine()) == null)
        		signature = line;
        }
        br.close();
        
        byte[] signByte = Base64.getDecoder().decode(signature.getBytes());
    
        return signByte;
        
    }

	
	
}
