package dk.emstar.network.tls.privatekeyinjector;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Created by Meang Akira Tanaka (mat013) on 5/29/18.
 */
public class Main {

    private static final String JKS = "JKS";
    private static final String PKCS_12 = "PKCS12";

    public static void main(String[] args) throws Exception {

        Main main = new Main();
        main.execute(args);

    }

    private void execute(String[] args) throws Exception{
        Map<String, Object> parsedArguments = parseArgument(args);

        // first item
        String password = (String) parsedArguments.get("-password");
        String inputFilename = (String) parsedArguments.get("-inputfilename");
        String outputName = (String) parsedArguments.get("-outputfilename");
        String keyFile = (String) parsedArguments.get("-keyfile");
        String keyAlias = (String) parsedArguments.get("-keyalias");

        Map<String, String> aliases = parseMappings((List<String>) parsedArguments.get("-mappings"));

        char[] passwordArray = password.toCharArray();

        KeyStore sourceKeystore = loadJKSKeyStore(inputFilename, passwordArray);
        PrivateKey privateKey = extractPrivateKey(keyFile, keyAlias, passwordArray);
        KeyStore result = buildEntries(aliases, passwordArray, sourceKeystore, privateKey);
        persist(passwordArray, result, outputName);
    }

    private KeyStore buildEntries(Map<String, String> aliases, char[] passwordArray, KeyStore sourceKeystore, PrivateKey key) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore result = newPKCS12Keystore(passwordArray);

        Enumeration<String> aliasEnumerator = sourceKeystore.aliases();
        while(aliasEnumerator.hasMoreElements()) {
            String alias = aliasEnumerator.nextElement();
            if(aliases.containsKey(alias)) {
                String mappedAlias = aliases.get(alias);
                System.out.printf("Adding private key entry %s from %s\r\n", mappedAlias, alias);
                result.setKeyEntry(mappedAlias, key, passwordArray, new Certificate[]{sourceKeystore.getCertificate(alias)});
            } else {
                System.out.printf("Adding entry %s\r\n", alias);
                result.setCertificateEntry(alias, sourceKeystore.getCertificate(alias));
            }
        }
        return result;
    }

    private Map<String, String> parseMappings(List<String> mappings) {
        Map<String, String> result = new HashMap<>();
        for (String mapping : mappings) {
            String[] tokens = mapping.split("@@");
            result.put(tokens[0], tokens[tokens.length < 2 ? 0 : 1]);
        }
        return result;
    }

    private Map<String,Object> parseArgument(String[] args) {
        Map<String, Object> result = new HashMap<>();

        List<String> subArgs = new ArrayList<>();
        result.put("*", subArgs);
        for (String arg : args) {
            if(arg.startsWith("-")) {
                subArgs = new ArrayList<>();
                result.put(arg, subArgs);
            } else {
                subArgs.add(arg);
            }
        }

        return result;
    }

    private KeyStore newPKCS12Keystore(char[] passwordArray) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore result = KeyStore.getInstance(PKCS_12);
        result.load(null, passwordArray);
        return result;
    }

    private void persist(char[] passwordArray, KeyStore result, String outputName) throws Exception {
        try (OutputStream fileOutputStream = new FileOutputStream(outputName)) {
            result.store(fileOutputStream, passwordArray);
        }
    }

    private PrivateKey extractPrivateKey(String filename, String alias, char[] passwordArray) throws Exception {
        KeyStore keystore = KeyStore.getInstance(PKCS_12);
        try (InputStream inputStream = new FileInputStream(filename)) {
            keystore.load(inputStream, passwordArray);
        }

        return (PrivateKey) keystore.getKey(alias, passwordArray);
    }

    private static KeyStore loadJKSKeyStore(String inputFilename, char[] passwordArray) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(JKS);
        keyStore.load(new FileInputStream(inputFilename), passwordArray);
        return keyStore;
    }
}
