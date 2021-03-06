import java.io.*;
import java.util.ArrayList; 
import java.util.HashMap; 

class FindMissing {
    
    private static ArrayList<String> foundPasswords;
    private static ArrayList<String> missingPasswords;
    private static HashMap<String, String> userFullnames;

    public static void main(String args[]){
        if(args.length != 3){
            System.out.println("usage: java FindMissing foundPath plainPath passwordPath\n");
            return;
        }
    
        foundPasswords = new ArrayList<String>();
        missingPasswords = new ArrayList<String>();
        userFullnames = new HashMap<String, String>();
        
        FileInputStream fstream;
        DataInputStream in;
        BufferedReader br;
        
        try {
            // Open the file that is the first 
            // command line parameter
            fstream = new FileInputStream(args[0]);
            
            // Get the object of DataInputStream
            in = new DataInputStream(fstream);
            br = new BufferedReader(new InputStreamReader(in));
            String strLine;
            
            //Read File Line By Line
            String username;
            while ((strLine = br.readLine()) != null)   {
                username = strLine.substring(0, strLine.indexOf(":"));
                if(!foundPasswords.contains(username))
                    foundPasswords.add(username);
            }
            
            //Close the input stream
            in.close();
        } catch (Exception e){
           System.err.println("Error: " + e.getMessage());
           e.printStackTrace();
        }
        
        try {
            // Open the file that is the first 
            // command line parameter
            fstream = new FileInputStream(args[2]);
            
            // Get the object of DataInputStream
            in = new DataInputStream(fstream);
            br = new BufferedReader(new InputStreamReader(in));
            String strLine;
            
            //Read File Line By Line
            String username, fullname;
            while ((strLine = br.readLine()) != null)   {
                username = strLine.substring(0, strLine.indexOf(":"));
                if(!foundPasswords.contains(username)){
                    userFullnames.put(username, strLine);
                }
            }
            
            //Close the input stream
            in.close();
        } catch (Exception e){
           System.err.println("Error: " + e.getMessage());
           e.printStackTrace();
        }
        
        try {
            // Open the file that is the first 
            // command line parameter
            fstream = new FileInputStream(args[1]);
            
            // Get the object of DataInputStream
            in = new DataInputStream(fstream);
            br = new BufferedReader(new InputStreamReader(in));
            String strLine;
            
            // Read File Line By Line
            String username;
            while ((strLine = br.readLine()) != null)   {
                // Print the content on the console
                username = strLine.substring(0, strLine.indexOf(":"));
                if(!foundPasswords.contains(username))
                    System.out.printf("%15s   %s\n", strLine, userFullnames.get(username));
            }
            
            //Close the input stream
            in.close();
        } catch (Exception e){
           System.err.println("Error: " + e.getMessage());
           e.printStackTrace();
        }
        
        System.out.printf("\n-------\nFound %d usernames\n Missing %d\n-------\n", foundPasswords.size(), 4096-foundPasswords.size());
    }
}
