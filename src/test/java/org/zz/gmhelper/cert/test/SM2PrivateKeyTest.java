package org.zz.gmhelper.cert.test;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.SM2PrivateKey;
import org.zz.gmhelper.cert.SM2PublicKey;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SM2PrivateKeyTest {
    @Test
    public void testEncoded() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = SM2Util.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();


        SM2PublicKey sm2PublicKey = new SM2PublicKey(publicKey.getAlgorithm(), publicKey);
        SM2PrivateKey sm2PrivateKey1 = new SM2PrivateKey(privateKey, publicKey);
        SM2PrivateKey sm2PrivateKey2 = new SM2PrivateKey(privateKey, sm2PublicKey);
        String nativePriDER = ByteUtils.toHexString(privateKey.getEncoded());
        String sm2PriDER1 = ByteUtils.toHexString(sm2PrivateKey1.getEncoded());
        String sm2PriDER2 = ByteUtils.toHexString(sm2PrivateKey2.getEncoded());
        if (nativePriDER.equalsIgnoreCase(sm2PriDER1)) {
            Assert.fail();
        }
        if (!sm2PriDER1.equalsIgnoreCase(sm2PriDER2)) {
            Assert.fail();
        }
        System.out.println("Native EC Private Key DER:\n" + nativePriDER.toUpperCase());
        System.out.println("SM2 EC Private Key DER:\n" + sm2PriDER1.toUpperCase());
    }

    @Test
    public void test1() throws Exception {
        KeyPair keyPair = SM2Util.generateKeyPair();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();


        byte[] publicBytes = publicKey.getEncoded();

        X509EncodedKeySpec eks = new X509EncodedKeySpec(publicBytes);

        KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);

        BCECPublicKey pubKey = (BCECPublicKey) kf.generatePublic(eks);


        byte[] prvBytes22 = privateKey.getEncoded();

        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(prvBytes22);

        KeyFactory kf22 = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);

        PrivateKey pvk = kf22.generatePrivate(eks2);

        BCECPrivateKey priKey = (BCECPrivateKey) pvk;

        String str = "abc123测试";
        byte[] encryptedData = SM2Util.encrypt(pubKey, str.getBytes(StandardCharsets.UTF_8));
        System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
        byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
        System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
        System.out.println("SM2 decrypt result:\n" + new String(decryptedData));
    }


}
