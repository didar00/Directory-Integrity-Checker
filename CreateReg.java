import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CreateReg
{
    public static final String CONTROL = "This is a private key file";
    private String priKeyPath;
    private String logPath;
    private String regPath;

    public CreateReg(String priKeyPath, String logPath, String regPath) throws IOException
    {
    	this.priKeyPath = priKeyPath;
    	this.logPath = logPath;
    	this.regPath = regPath;
    	
    	// checks if log and registry files exist, if not, creates new ones
    	File logFile = new File(logPath);
    	if(!logFile.exists())
    	    FileOperations.initializeLog();
    	File regFile = new File(regPath);
    	if(!regFile.exists())
    		FileOperations.initializeReg();
    	
    }

    /** 
     * 
     * Compares the end of private key file and 
     * control line string to verify the password.
     * If no verification happens, program terminates 
     * after writing to log file
     * @throws IOException 
     * 
    */
    public void passwordVerification() throws IOException
    {
        String key = FileOperations.getContent(priKeyPath);
        
        int start = key.length() - CONTROL.length();
        int end = key.length();
        if (!(key.substring(start, end)).equals(CONTROL))
        {
            // time stamp in format of dd-MM-yyyy HH:mm:ss
            String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
            String event = timestamp + ": Wrong password attempt!";
            FileOperations.updateLogFile(event);
            // exists program
            System.exit(0);
        }
        
    }



    /**
     * creates registry file with their hash values
     * @throws IOException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws CertificateException 
     * @throws SignatureException 
     * @throws InvalidKeyException 
     * @throws UnrecoverableKeyException 
     */
    public void createRegFile(String folderPath, String hashMode) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, CertificateException, KeyStoreException
    {
        File folder = new File(folderPath);
        File[] files = folder.listFiles();
        int fileCount = 0;
        
        // writes the registry file creation to log file
        String timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
        String refFilePath = regPath;
        StringBuilder event = new StringBuilder(timestamp);
        event.append(": Registry file is created at ").append(refFilePath).append("!\n");
        FileOperations.updateLogFile(event.toString());

        /**
         * calculates each file's hash value that is in
         * the directory and stores the values in the 
         * registry file
         */
        for (File file : files)
        {
            if (file.isFile())
            {
                // gets absolute path of the file
                String filePath = file.getAbsolutePath();
                // gets the content of the file
                String content = FileOperations.getContent(filePath);
                // calculates the hash value of file
                String hashValue = getHash(content, hashMode);
                StringBuilder registry = new StringBuilder();
                // format of : [Path_of_file1] H(file1)
                registry.append(filePath)
                        .append(" ")
                        .append(hashValue)
                		.append("\n");
                FileOperations.updateRegFile(registry.toString());
                
                // writes to log file
                timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
                event = new StringBuilder(timestamp);
                event.append(": ").append(filePath).append(".\n");
                FileOperations. updateLogFile(event.toString());
                fileCount++;
            }
        }

        timestamp = new SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new Date());
        event = new StringBuilder(timestamp);
        event.append(": ").append(fileCount).append(" files are added to the registry and registry creation is finished!\n");
        FileOperations.updateLogFile(event.toString());

        /**
         * calculates registry file's own hash value 
         * and writes the end of the file
         */
        String regContent = FileOperations.getContent(regPath);
        String signature = sign(regContent, hashMode);
        FileOperations.updateRegFile(signature);

    }

    private String sign(String content, String mode) throws SignatureException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, InvalidKeyException
    {
        PrivateKey privateKey = CreateCert.getPrivateKey();
        
        FileInputStream is = new FileInputStream("ichecker.jks");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "111111".toCharArray());
        
        Signature signature = null;
        
        if (mode.equals("MD5"))
        	signature = Signature.getInstance("MD5withRSA");
        else if (mode.equals("SHA-256"))
        	signature = Signature.getInstance("SHA256withRSA");
        
        signature.initSign(privateKey);

        byte[] messageBytes = Files.readAllBytes(Paths.get(regPath));

        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();
        String signatureStr = new String(Base64.getEncoder().encode(digitalSignature));
        return signatureStr;

    }


    public static String getHash(String content, String mode) throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        String hashStr = null;

        if (mode.equals("SHA-256"))
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes("UTF-8"));
            hashStr = new BigInteger(hash).toString(2);
        }
        else if (mode.equals("MD5"))
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(content.getBytes());
            byte[] hash = md.digest();
            hashStr = new BigInteger(hash).toString(2);
        }
        else
        {
            System.out.println("Invalid Hash Function");
            System.out.println("System exit: 0");
            System.exit(0);
        }
        
        return hashStr;
    }
    

}
