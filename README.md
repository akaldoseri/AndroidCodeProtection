# Android Code Protection

This repo shows an example of Android code protection.



## backend_server

To run the backend server.
- Host the code in any PHP server (e.g apache).
- Install composer in your machine and run `composer install`.
- Ensure that `certs` directory contain the recent Google certificate from (https://developer.android.com/training/articles/security-key-attestation.html). Note, our code works with certificate, you need to add the other certificates as well.
- The android code is encapsulated in `classes.dex` file. We compile 10 sorting algorithms rom `https://github.com/diptangsu/Sorting-Algorithms/tree/master/Java`. So thank you for this. If you want to use your own code. Simple do the following:
    - create Android project with empty Activity.
    - Write your own secret classes/code.
    - Compile the project into APK.
    - Unzip the APK file and extract the class file. It should be the `classes3.dex`.
- Generate your own certificate (private/public) using any tool (e.g openssl) and store them in `certs`. I am attaching my own certficates an example : `example.com.key` and `example.com.pem`


## android_app

To run the android app.

- Open the project with Android Studio or import it. 
- In the `MainActivity` class, change GET_NONCE_URL and GET_VERDICT_URL URLs to match your server side URLs. (HTTPS are not needed for testing.)
- Copy the content of your generated public certificate and assign it to `certText` variable at method `verifyCodeSignature` line 513. Otherwise, you can can keep it as it is if you want to use the example certificate `example.com.pem`.
 

 # References and acknowledgement 
There are many resources I used to make this project works. So I am really thankful to them.
These are some of the references that I recall.

- Sorting algorithms in multiple languages., https://github.com/diptangsu/Sorting-Algorithms/tree/master/Java
- Verifying hardware-backed key pairs with Key Attestation, Android.com, https://developer.android.com/training/articles/security-key-attestation.html).
- 3 ways for Dynamic Code Loading in Android, erev0s, https://erev0s.com/blog/3-ways-for-dynamic-code-loading-in-android/.
- How to RSA encrypt using a X509 public with cert file on Android?https://stackoverflow.com/questions/23823932/how-to-rsa-encrypt-using-a-x509-public-with-cert-file-on-android
- Read public key from file in keystore, L.Butz,https://stackoverflow.com/a/26711907
- Creating OpenSSL x509 certificates, https://adfinis.com/en/blog/openssl-x509-certificates/
- How to store and retrieve an RSA public key in Android keystore which is generated from server side application?, https://stackoverflow.com/a/49581469
- How to use phpseclib to verify that a certificate is signed by a public CA?, https://stackoverflow.com/a/48994119
- phpseclib: X.509 Tutorial, https://phpseclib.sourceforge.net/new/x509/tutorial.html
- Generating Random String Using PHP,geeksforgeeks, https://www.geeksforgeeks.org/generating-random-string-using-php/
- How to use phpseclib to verify that a certificate is signed by a public CA?, https://stackoverflow.com/a/48994119