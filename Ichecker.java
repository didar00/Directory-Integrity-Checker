import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Ichecker
{
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, SignatureException, CertificateException, KeyStoreException
    {
        
        
        /**
         *  parameter definitions
         */
        String function,
        		priKey,
        		pubKeyCert,
        		regFile,
        		logFile,
        		hashMode,
        		folderPath;
        
        function = priKey = pubKeyCert = regFile = logFile = hashMode = folderPath = null;
        
        function = args[0];
        
        for (int i = 1; i < args.length; i++)
        {
        	if (args[i].equals("-k"))
        		priKey = args[i+1];
        	else if (args[i].equals("-c"))
        		pubKeyCert = args[i+1];
        	else if (args[i].equals("-r"))
        		regFile = args[i+1];
        	else if (args[i].equals("-p"))
        		folderPath = args[i+1];
        	else if (args[i].equals("-l"))
        		logFile = args[i+1];
        	else if (args[i].equals("-h"))
        		hashMode = args[i+1];
        }

        
        if (function.equals("createCert"))
        {
        	CreateCert cc = new CreateCert(priKey, pubKeyCert);
        	
        	// creates private key file in the specified path
            CreateCert.priKeyFileGenerator();
            
            // asks user for password
            System.out.println("Please, enter password: ");
            Scanner sc = new Scanner(System.in);
            String password = sc.nextLine();
            String hashedPass = CreateCert.hashPassword(password);

            // encode private key file with user password
            CreateCert.encodePriKeyFile(hashedPass);
            
            
/*
            String password2 = sc.nextLine();
            

            // MD5 hash operation is applied to password
            String hashedPass2 = cc.hashPassword(password2);

            //  decodes encoded private key file
            cc.decodePriKeyFile(hashedPass2);
*/

            sc.close();
        }
        else if (function.equals("createReg")) // creates registry file
        {
        	FileOperations fo = new FileOperations(priKey, logFile ,regFile);
            CreateReg cr = new CreateReg(priKey, logFile, regFile);

            // take the password from user
            System.out.println("Please, enter password: ");
            Scanner sc = new Scanner(System.in);
            String password = sc.nextLine();

            // MD5 hash operation is applied to password
            String hashedPass = CreateCert.hashPassword(password);

            //  decodes encoded private key file
            CreateCert.decodePriKeyFile(priKey, hashedPass);

            // verifies the password entered by the user
            // if verification fails, program exits
            cr.passwordVerification();
            
            // initializes the registry file in the path that is specified in command line
            cr.createRegFile(folderPath, hashMode);


        }
        else if (function.equals("check"))
        {
        	FileOperations fo = new FileOperations(priKey, logFile ,regFile);
        	Check check = new Check(regFile, priKey, folderPath, hashMode);
        	check.signatureVerification();
        }



    }
    
   

}