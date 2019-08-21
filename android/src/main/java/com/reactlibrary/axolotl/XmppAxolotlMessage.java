package com.reactlibrary.axolotl;

import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.reactlibrary.RNLibsignalProtocolModule;
import com.reactlibrary.utils.Compatibility;

public class XmppAxolotlMessage {
    private static final String KEYTYPE = "AES";
    private static final String CIPHERMODE = "AES/GCM/NoPadding";
    private static final String PROVIDER = "BC";

    public byte[] innerKey;
    public byte[] ciphertext = null;
    public byte[] authtagPlusInnerKey = null;
    public byte[] iv = null;
    public final List<XmppAxolotlSession.AxolotlKey> keys;
    public final String from;
    public final int sourceDeviceId;
    public XmppAxolotlMessage(String from, int sourceDeviceId) {
        this.from = from;
        this.sourceDeviceId = sourceDeviceId;
        this.keys = new ArrayList<>();
        this.iv = generateIv();
        this.innerKey = generateKey();
    }
    public XmppAxolotlMessage(String from, int sourceDeviceId, byte[] iV, ArrayList<XmppAxolotlSession.AxolotlKey> keysList, byte[] cipherText) {
        this.from = from;
        this.sourceDeviceId = sourceDeviceId;
        this.keys = keysList;
        iv = iV;
        ciphertext = cipherText;
    }

    private static byte[] generateKey() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KEYTYPE);
            generator.init(128);
            return generator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            Log.e(RNLibsignalProtocolModule.RN_LIBSIGNAL_ERROR, e.getMessage());
            return null;
        }
    }

    private static byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    void encrypt(String plaintext) throws CryptoFailedException {
        try {
            SecretKey secretKey = new SecretKeySpec(innerKey, KEYTYPE);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Compatibility.twentyEight() ? Cipher.getInstance(CIPHERMODE) : Cipher.getInstance(CIPHERMODE, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            this.ciphertext = cipher.doFinal(plaintext.getBytes());
            if (this.ciphertext != null) {
                this.authtagPlusInnerKey = new byte[16+16];
                byte[] ciphertext = new byte[this.ciphertext.length - 16];
                System.arraycopy(this.ciphertext,0,ciphertext,0,ciphertext.length);
                System.arraycopy(this.ciphertext,ciphertext.length,authtagPlusInnerKey,16,16);
                System.arraycopy(this.innerKey,0,authtagPlusInnerKey,0,this.innerKey.length);
                this.ciphertext = ciphertext;
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException
                | InvalidAlgorithmParameterException e) {
            throw new CryptoFailedException(e);
        }
    }

    void addDevice(XmppAxolotlSession session) {
        XmppAxolotlSession.AxolotlKey key;
        if (authtagPlusInnerKey != null) {
            key = session.processSending(authtagPlusInnerKey);
        } else {
            key = session.processSending(innerKey);
        }
        if (key != null) {
            keys.add(key);
        }
    }

    private byte[] unpackKey(XmppAxolotlSession session, Integer sourceDeviceId) throws CryptoFailedException {
        ArrayList<XmppAxolotlSession.AxolotlKey> possibleKeys = new ArrayList<>();
        for(XmppAxolotlSession.AxolotlKey key : keys) {
            if (key.deviceId == sourceDeviceId) {
                possibleKeys.add(key);
            }
        }
        if (possibleKeys.size() == 0) {
            throw new NotEncryptedForThisDeviceException();
        }
        return session.processReceiving(possibleKeys);
    }

    public String decrypt(XmppAxolotlSession session, Integer sourceDeviceId) throws CryptoFailedException {
        String plaintext = null;
        byte[] key = unpackKey(session, sourceDeviceId);
        if (key != null) {
            try {
                if (key.length >= 32) {
                    int authtaglength = key.length - 16;
                    byte[] newCipherText = new byte[key.length - 16  + ciphertext.length];
                    byte[] newKey = new byte[16];
                    System.arraycopy(ciphertext, 0, newCipherText, 0, ciphertext.length);
                    System.arraycopy(key, 16, newCipherText, ciphertext.length, authtaglength);
                    System.arraycopy(key,0,newKey,0,newKey.length);
                    ciphertext = newCipherText;
                    key = newKey;
                }

                Cipher cipher = Compatibility.twentyEight() ? Cipher.getInstance(CIPHERMODE) : Cipher.getInstance(CIPHERMODE, PROVIDER);
                SecretKeySpec keySpec = new SecretKeySpec(key, KEYTYPE);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                plaintext = new String(cipher.doFinal(ciphertext));

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                    | InvalidAlgorithmParameterException | IllegalBlockSizeException
                    | BadPaddingException | NoSuchProviderException e) {
                throw new CryptoFailedException(e);
            }
        }
        return plaintext;
    }
}
