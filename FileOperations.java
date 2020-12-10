import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

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

    private static void write(String data, String file) throws IOException
    {
        BufferedWriter bw = new BufferedWriter(new FileWriter(file, true));
        bw.write(data);
        bw.close();
    }

}
