package com.example.codeprotectiondemo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import android.os.StrictMode;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import android.view.View;

import org.json.JSONArray;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;

public class MainActivity extends AppCompatActivity {

    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String KEY_ALIAS = "key1";
    public static final String GET_NONCE_URL = "http://192.168.71.111/www/cp/get_nonce.php";
    public static final String GET_VERDICT_URL = "http://192.168.71.111/www/cp/get_verdict.php";
    byte[] encryptedBytesGlobal;
    String encryptedBytesBase64;

    String nonce = "";
    String verdict = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

    }


    public String decryptTestBase64(String cipherText64, int status) {
        Cipher cipher = null;
        try {
            byte[] cipherText = Base64.decode(cipherText64, 0);

            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(KEY_ALIAS));
            byte[] iv = cipher.getIV();
            byte[] decryptedBytes = cipher.doFinal(cipherText);

            String x = new String(decryptedBytes, StandardCharsets.UTF_8);
            return x;


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public void decryptTestBase64(String cipherText64) {
        Cipher cipher = null;
        try {
            byte[] cipherText = Base64.decode(cipherText64, 0);

            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(KEY_ALIAS));
            byte[] iv = cipher.getIV();
            byte[] decryptedBytes = cipher.doFinal(cipherText);

            String x = new String(decryptedBytes, StandardCharsets.UTF_8);
            Log.d("woot", x);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void decryptText() {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(KEY_ALIAS));
            byte[] iv = cipher.getIV();
            byte[] decryptedBytes = cipher.doFinal(encryptedBytesGlobal);

            String x = new String(decryptedBytes, StandardCharsets.UTF_8);
            Log.d("woot", x);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    // https://stackoverflow.com/questions/23823932/how-to-rsa-encrypt-using-a-x509-public-with-cert-file-on-android
    public void encryptText(String data) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, getCertificateChain(KEY_ALIAS)[0]);
            byte[] iv = cipher.getIV();
            byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            encryptedBytesGlobal = encryptedData;

            String x = Base64.encodeToString(encryptedData, 0);
            encryptedBytesBase64 = x;
            Log.d("woot", x);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public boolean generateKeys(String alias) {
        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);

            String attestationChallenge = nonce;
            int ORIGINATION_TIME_OFFSET = 1000000;
            int CONSUMPTION_TIME_OFFSET = 2000000;
            Date now = new Date();
            Date originationEnd = new Date(now.getTime() + ORIGINATION_TIME_OFFSET);
            Date consumptionEnd = new Date(now.getTime() + CONSUMPTION_TIME_OFFSET);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537)))
                    .setKeyValidityStart(now)
                    .setKeyValidityForOriginationEnd(originationEnd)
                    .setKeyValidityForConsumptionEnd(consumptionEnd)
                    //.setIsStrongBoxBacked(true) //google pixel phones
                    .setAttestationChallenge(attestationChallenge.getBytes())
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);

            keyPairGenerator.initialize(builder.build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Log.d("woot", "keys Generated successfully");

            return true;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return false;
    }

    public PrivateKey getPrivateKey(String alias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

            //Log.d("woot",privateKey.toString());
            return privateKey;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public PublicKey getPublicKey() {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
//            X509Certificate cert  =  (X509Certificate) (keyStore.getCertificateChain(KEY_ALIAS)[0]);
            Certificate cert = (keyStore.getCertificateChain(KEY_ALIAS)[0]);
            PublicKey pk = cert.getPublicKey();
            String key = pk.toString();

            String base64 = Base64.encodeToString(pk.getEncoded(), Base64.DEFAULT);
            Log.d("woot", base64);
            Log.d("woot", pk.getFormat());
            return pk;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public Certificate[] getCertificateChain(String alias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            Certificate[] certificates = keyStore.getCertificateChain(alias);
            return certificates;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public void printCertficates() {
        String alias = KEY_ALIAS;
        Certificate[] certs = getCertificateChain(alias);
        X509Certificate cert;

        Log.d("woot", certs.length + "");
        for (int i = 0; i < certs.length; i++) {
            try {

                cert = (X509Certificate) certs[i];
                String base64 = Base64.encodeToString(cert.getEncoded(), Base64.DEFAULT);
                Log.d("woot", base64);

            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }

        }
    }

    public String[] GetCertficates() {

        int x = 2;

        String alias = KEY_ALIAS;
        Certificate[] certs = getCertificateChain(alias);
        String[] certsPEM = new String[certs.length];
        X509Certificate cert;

        // Log.d("woot",certs.length+"");
        for (int i = 0; i < certs.length; i++) {
            try {

                cert = (X509Certificate) certs[i];
                String base64 = Base64.encodeToString(cert.getEncoded(), Base64.DEFAULT);
                certsPEM[i] = base64;
                //Log.d("woot",base64);

            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }

        }

        return certsPEM;
    }

    public void getNonce() {

        String Url = GET_NONCE_URL, query = "";

        InputStream inputStream;
        HttpURLConnection urlConnection = null;
        byte[] outputBytes;
        String responseData;

        try {
            URL url = new URL(Url);
            urlConnection = (HttpURLConnection) url.openConnection();
            outputBytes = query.getBytes("UTF-8");
            urlConnection.setRequestMethod("POST");
            urlConnection.setDoOutput(true);
            urlConnection.setConnectTimeout(15000);
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.connect();

            OutputStream os = urlConnection.getOutputStream();
            os.write(outputBytes);
            os.flush();
            os.close();

            inputStream = new BufferedInputStream(urlConnection.getInputStream());
            responseData = convertStreamToString(inputStream);
            nonce = responseData;
            Log.d("woot", "Nonce received!!");
            Log.d("woot", responseData);

            //enter statements that can cause exceptions
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) // Make sure the connection is not null.
                urlConnection.disconnect();
        }

    }

    public void getVerdict(String[] certs) {

        String Url = GET_VERDICT_URL, query = "";
        JSONArray jsonArray = new JSONArray(Arrays.asList(certs));
        query = jsonArray.toString();

        InputStream inputStream;
        HttpURLConnection urlConnection = null;
        byte[] outputBytes;
        String responseData;

        try {
            URL url = new URL(Url);
            urlConnection = (HttpURLConnection) url.openConnection();
            outputBytes = query.getBytes("UTF-8");
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("key", "value");
            urlConnection.setDoOutput(true);
            urlConnection.setConnectTimeout(15000);
            urlConnection.setRequestProperty("Content-Type", "application/json");
            urlConnection.connect();

            OutputStream os = urlConnection.getOutputStream();
            os.write(outputBytes);
            os.flush();
            os.close();

            inputStream = new BufferedInputStream(urlConnection.getInputStream());
            responseData = convertStreamToString(inputStream);
            verdict = responseData;

            Log.d("woot", "Attested code received!");
            Log.d("woot", responseData);

            //enter statements that can cause exceptions
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) // Make sure the connection is not null.
                urlConnection.disconnect();
        }

    }

    public String convertStreamToString(InputStream is) {

        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        StringBuilder sb = new StringBuilder();

        String line = null;
        try {
            while ((line = reader.readLine()) != null) {
                sb.append((line + "\n"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return sb.toString();
    }

    public void GetNonceClick(View view) {
        Log.d("woot", "Getting nonce ...................... ");
        getNonce();
    }

    public void StartAttestationClick(View view) {

        Log.d("woot", "Starting attestation ...................... ");

        //generate keys
        generateKeys(KEY_ALIAS);
        //get certificate chain
        String[] certs = GetCertficates();
        //start attestation to get verdict
        getVerdict(certs);

        //split verdict into signature and code
        String[] result = verdict.split("#");
        String[] signatureText = result[0].split("@");
        String[] codeText = result[1].split("@");

        //decrypt signature
        String signature64 = "";
        for (int i = 0; i < signatureText.length; i++) {
            signatureText[i] = decryptTestBase64(signatureText[i], 0);
            signature64 = signature64 + signatureText[i];
        }

        //decrypt cipher
        String code64 = "";
        for (int i = 0; i < codeText.length; i++) {
            codeText[i] = decryptTestBase64(codeText[i], 0);
            code64 = code64 + codeText[i];
        }

        //execute the secret code
        if(verifyCodeSignature(code64,signature64)){
            LoadCode(code64);
            Log.d("woot", "The attested code executed successfully");
        }else{
            Log.d("woot", "Verification failed for attested code");
        }

    }

    public void LoadCode(String code) {
        CustomClassLoader customClassLoader = new CustomClassLoader();
        customClassLoader.loadCode(code);
    }

    // ref : https://stackoverflow.com/a/26711907
    // create cert : https://adfinis.com/en/blog/openssl-x509-certificates/
    // load key : https://stackoverflow.com/a/49581469
    public Boolean verifyCodeSignature(String code, String codeSignature) {

        try {

            String certText = "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDozCCAougAwIBAgIUcKsG83+0uLyWlAjQ1hqL18aZTvYwDQYJKoZIhvcNAQEL\n" +
                    "BQAwYTELMAkGA1UEBhMCYWExCzAJBgNVBAgMAmFhMQswCQYDVQQHDAJhYTELMAkG\n" +
                    "A1UECgwCYWExCzAJBgNVBAsMAmFhMQswCQYDVQQDDAJhYTERMA8GCSqGSIb3DQEJ\n" +
                    "ARYCYWEwHhcNMjIxMjE4MjI0ODIzWhcNMjQxMjE3MjI0ODIzWjBhMQswCQYDVQQG\n" +
                    "EwJhYTELMAkGA1UECAwCYWExCzAJBgNVBAcMAmFhMQswCQYDVQQKDAJhYTELMAkG\n" +
                    "A1UECwwCYWExCzAJBgNVBAMMAmFhMREwDwYJKoZIhvcNAQkBFgJhYTCCASIwDQYJ\n" +
                    "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKtYnCt8UhnOlgapQ4ftjtPSR8q8ZO1g\n" +
                    "qP35GmnXYiDfsccgtpwkMl59yXMOcibHGHBeVMPqN1Cdjh15FJxg4n/1XNN8isDp\n" +
                    "aeQY8/GFNCfUnRJFr4+68Zk3gwZCDNt8LRt44Cijmx+vR7iz2V2/UU4TH+WsxyiB\n" +
                    "GHKIco642mvBCsT8DruLk/jL2ZrazXkb228wZMhkCaWtNRQjj9cI0NwdtaQGDQks\n" +
                    "qG7wOtgDNAcQerYcrB1zHoJzrVxtpOIR5VD3Elf2KMz3/vBcmRn3tohks+/37HTf\n" +
                    "JZA9QinlK9TG1OeF9uqYBtFGiLBd3btyubYLMOMo0x8pCmiMgSEs5scCAwEAAaNT\n" +
                    "MFEwHQYDVR0OBBYEFGqs6GqqVQCv2/sCd2/0pDg+mXCXMB8GA1UdIwQYMBaAFGqs\n" +
                    "6GqqVQCv2/sCd2/0pDg+mXCXMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n" +
                    "BQADggEBAGdojDZ7fsxTswSK0mDsHJeMV2bq0si+aKXo/278STCHK8WyHVXBSKNS\n" +
                    "HTlabaCRWEtwN/Z7mheKmtG/Dho29xUaZ4yDEdkxAuQIdDt2rba833YNt2P+A73+\n" +
                    "MYQvL9r+JQ2fryCTy8LL4ySMclfZpylZwG6XjOM6/Ehh9s/FzG9Ze7vUkDk3zq5P\n" +
                    "DsRFQVL+X6CVDt16TxY8+ltybkv6kaj2Dp5iF4JH9uPc8+kQ1ZF2HbTcV5g7ht9n\n" +
                    "GmJyJ5XggKi7KNQZCIW0ALaaow+F7YrKBH1u81liKu9ME7qIR4af86r3CNyGB5g9\n" +
                    "OJgc+fnKY02B9pCOkIsM7Bt4pT23aH4=\n" +
                    "-----END CERTIFICATE-----";

                    //Log.d("woot",certText);

                    X509Certificate codecert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certText.getBytes(StandardCharsets.UTF_8)));
                    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                    KeyProtection keyProtection = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_VERIFY)
                            .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                            .build();
                    keyStore.load(null);
                    keyStore.deleteEntry("codecert");
                    keyStore.setEntry("codecert", new KeyStore.TrustedCertificateEntry(codecert), keyProtection);

                    KeyStore keyStore2 = KeyStore.getInstance("AndroidKeyStore");
                    keyStore2.load(null);
                    Certificate codecert2 = keyStore2.getCertificate("codecert");

                    //  String signatureText = "WesE3ks62MlP+5Q6/cM1DW4B2IzpvrxCb7Oc1ybTKssMBpT7si755lyzD8ieCh9buMtXrtC81osvqIyoENuGKWorXxUN2tvB7JjdciHFuBFpWs2LLwbCXgVRMRYtDEZmhN2ycQl9An9t3tfd9Pu3JkEm/PsCC/KUCg2cYzZx3o1QgW1hqgVwWrGPNyeboQ2quqeS15HjHpSWwIWltLBgDogm5Z/ctGUmv9UTnt4kKg2temyzaSPEY8mkn2Hq6wyrkuT/Mwg38QGf00G3VXH5ejuxLecYJqryWZ0DOqhOWad1ZRuxd15heu/Q6wad7gOl1AeEmsUOA45aM4dh1zbgWQ==";
                    byte[] signatureByte = Base64.decode(codeSignature,0);
                    Signature signature = Signature.getInstance("SHA256withRSA/PSS");
                    signature.initVerify(codecert2);
                    signature.update(code.getBytes(StandardCharsets.UTF_8));
                    boolean flag = signature.verify(signatureByte);
                    Log.d("woot",flag?"Code successfully verified":"no");
                    return  flag;



        }  catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return false;

    }
}