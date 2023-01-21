<?php

// References:
// https://stackoverflow.com/a/48994119
// https://phpseclib.sourceforge.net/new/x509/tutorial.html

ini_set('display_errors', true);
error_reporting(E_ALL ^ E_NOTICE);
require __DIR__ . '/vendor/autoload.php';

use phpseclib3\File\X509;
use Sop\ASN1\Type\UnspecifiedType;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;


$ATTESTATION_CHALLENGE ="key attestation challenge";
$ATTESTATION_APPLICATION_ID ="com.example.codeprotectiondemo";
$ATTESTATION_APPLICATION_HASH ="J0KetPuRpQ1FJWGH/iiwm8yjIt2V/gxS1UDdn6XgNz0=";

// $certs = array();
// $cert0 = file_get_contents("a73_certs/cert0.pem");
// $cert1 = file_get_contents("a73_certs/cert1.pem");
// $cert2 = file_get_contents("a73_certs/cert2.pem");
// $cert3 = file_get_contents("a73_certs/cert3.pem");

// array_push($certs,$cert0);
// array_push($certs,$cert1);
// array_push($certs,$cert2);
// array_push($certs,$cert3);

$certs = file_get_contents("php://input");
$certs = json_decode($certs, true);

$valid = true;


$google = file_get_contents("certs/google_ca.pem");
$device_root = $certs[count($certs)-1];


if(!(strcmp($google, $device_root)))
   $valid = $valid  && false;


for($i=0;$i<(count($certs)-1);$i++){
    
    $x509 = new X509();
    $x509->loadCA($certs[$i+1]);
    $cert = $x509->loadX509($certs[$i]);
    $valid = $valid &&  $x509->validateSignature();
}



    

if($valid){

    $x509 = new X509();
    $cert = $x509->loadX509($certs[0]);
    $extentions =  ($cert['tbsCertificate']['extensions'][0]['extnValue']);
    

    //decode extentions
    $der = $extentions;

    $seq = UnspecifiedType::fromDER($der)->asSequence();
    $attestationVersion = $seq->at(0)->asInteger()->intNumber();

    $attestationChallenge = $seq->at(4)->asOctetString()->string();
    
    $softwareEnforced = $seq->at(6)->asSequence();
    $attestationApplicationIdSeq = $softwareEnforced->getTagged(709)->asExplicit()->asOctetString()->string();
    $attestationApplicationIdDer = base64_encode($attestationApplicationIdSeq);

    $attestationApplicationIdSeq = UnspecifiedType::fromDER($attestationApplicationIdSeq)->asSequence();

    $attestationApplicationId = $attestationApplicationIdSeq->at(0)->asSet()->elements()[0]->asSequence()->at(0)->asOctetString()->string();
    $attestationApplicationHash = $attestationApplicationIdSeq->at(1)->asSet()->elements()[0]->asOctetString()->string();
    $attestationApplicationHash = base64_encode($attestationApplicationHash);

    $teeEnforced = $seq->at(7)->asSequence();

    $rootOfTrust = $teeEnforced->getTagged(704)->asExplicit()->asSequence();
    $deviceLocked = $rootOfTrust->at(1)->asBoolean();
    $verifiedBootState = $rootOfTrust->at(2)->asInteger()->intNumber();;


    $flag = false;


    if(
        ($attestationApplicationId == $ATTESTATION_APPLICATION_ID)
        && ($attestationApplicationHash  == $ATTESTATION_APPLICATION_HASH)
        && ($deviceLocked)
        && ($verifiedBootState  == 0)
        // && ($attestationChallenge == $ATTESTATION_CHALLENGE )

    )
        $flag = true;




    if($flag){

        //get secret
        $secret = base64_encode(file_get_contents("classes.dex"));
        //sign secret
        $sk = RSA::loadFormat('PKCS8', file_get_contents('certs/example.com.key'), $password=false);
        $signature =  $sk->withHash("sha256")->withPadding(RSA::SIGNATURE_PSS)->sign($secret);
        $signature =  base64_encode($signature);

        
        //encrypt
        $x509 = new X509();
        $certificate = $certs[0];
        $key = PublicKeyLoader::load($certificate, $password = false);
        $ciphertext ="";
        
        $secret = str_split($secret,200);
        for($i=0;$i<count($secret);$i++){
            $plaintext = $secret[$i];
            $ciphertext =  $ciphertext ."@". base64_encode($key->withPadding(RSA::ENCRYPTION_PKCS1)->encrypt($plaintext));
        }
        $ciphertext = ltrim($ciphertext, '@');

        
        $signaturetext ="";
        $signature = str_split($signature,200);
        for($i=0;$i<count($signature);$i++){
            $plaintext = $signature[$i];
            $signaturetext =  $signaturetext ."@". base64_encode($key->withPadding(RSA::ENCRYPTION_PKCS1)->encrypt($plaintext));
        }
        $signaturetext = ltrim($signaturetext, '@');

        


        echo $signaturetext."#".$ciphertext;
    }


}
