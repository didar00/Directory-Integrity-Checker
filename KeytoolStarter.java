import java.io.IOException;

public class KeytoolStarter
{
    public void start(String certificatePath)
    {

        try
        {
            String[] a = new String[] {"keytool", "-genkeypair", "-keyalg", "RSA", "-keysize", "2048", "-alias", "ichecker", "-keystore", "ichecker.jks", "-dname", "CN=icheck", "-storepass", "111111", "-keypass", "111111"};
            Process proc = new ProcessBuilder(a).start();
            // convert jks to p12
            proc.waitFor();
            String[] b = new String[] {"keytool", "-importkeystore", "-srckeystore", "ichecker.jks", "-destkeystore" ,"ichecker.p12", "-deststoretype", "PKCS12", "-deststorepass", "111111", "-srcstorepass", "111111"};
            proc = new ProcessBuilder(b).start();
            proc.waitFor();
            // get private key
            String[] c = new String[] {"openssl", "pkcs12", "-in", "ichecker.p12",  "-nodes", "-nocerts", "-out", "key.pem", "-password", "pass:111111"};
            proc = new ProcessBuilder(c).start();
            proc.waitFor();
            // get certificate
            String[] d = new String[] {"keytool", "-export", "-alias" ,"ichecker" ,"-keystore" ,"ichecker.jks", "-rfc", "-file", certificatePath, "-storepass", "111111"};
            proc = new ProcessBuilder(d).start();
        }catch(IOException e)
        {
            System.out.println("IO Exception");
        }
        catch(InterruptedException e2)
        {
            System.out.println("Interrupted Exception");
        }
    }
}
