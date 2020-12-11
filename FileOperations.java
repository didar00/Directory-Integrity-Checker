import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;

public class FileOperations
{
	private static String priKeyPath;
    private static String logPath;
    private static String regPath;
    
    public FileOperations(String priKey, String logFile, String regFile)
    {
    	priKeyPath = priKey;
    	logPath = logFile;
    	regPath = regFile;
    }
	
    public static void initializeLog() throws IOException
    {
    	FileWriter logFile = new FileWriter(logPath);
    }
    
    public static void initializeReg() throws IOException
    {
    	FileWriter regFile = new FileWriter(regPath);
    }
	
	public static void updateLogFile(String event) throws IOException
    {
        write(event, logPath);
    }

    public static void updateRegFile(String data) throws IOException
    {
        write(data, regPath);
    }
    
    /**
    *  reads file
    *  @return content
     * @throws IOException 
    */
    public static String getContent(String file) throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line = null;
        StringBuilder sb = new StringBuilder();
        while((line = br.readLine()) != null)
            sb.append(line);
        String content = sb.toString();
        br.close();
        return content;
    }
    
	/**
	 *  reads registry file except last line (which is signature) to authenticate signature
	 *  @return content
	  * @throws IOException 
	 */
	 public static String getContent() throws IOException
	 {
		 int lineCount = getRegFileSize();
	     BufferedReader br = new BufferedReader(new FileReader(regPath));
	     String line = null;
	     StringBuilder sb = new StringBuilder();
	     
	     while((line = br.readLine()) != null)
	     {
	    	 if (lineCount == 0)
	    		 break;
	    	 
	    	 sb.append(line);
	    	 lineCount--;
	     }
	     
	     String content = sb.toString();
	     br.close();
	     
	     return content;
	 }
     
	public static int getRegFileSize() throws IOException
	{
		int lineCount = 0;
		BufferedReader br = new BufferedReader(new FileReader(regPath));
	    String line = null;
	    while ((line = br.readLine()) != null)
	    	lineCount++;
	    br.close();
	     
	    return (lineCount-1);
	}

	
    /**
    *  reads registry file
    *  @return signature
     * @throws IOException 
    */
    public static byte[] getSignature() throws IOException
    {
    	int lineCount = getRegFileSize();
        BufferedReader br = new BufferedReader(new FileReader(regPath));
        String line = null;
        String signature = null;
        
        while((line = br.readLine()) != null)
        {
        	if (lineCount == 0)
        	{
        		signature = line;
        	}
        	lineCount--;
        }
        br.close();
        
        
        byte[] signByte = Base64.getDecoder().decode(signature);
    
        return signByte;
        
    }
    
    
    private static void write(String data, String file) throws IOException
    {
        BufferedWriter bw = new BufferedWriter(new FileWriter(file, true));
        bw.write(data);
        bw.close();
    }

}
