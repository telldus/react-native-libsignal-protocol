package com.reactlibrary.storage;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;

public class PreferenceManager {
    SharedPreferences pref;
    public PreferenceManager(Context context) {
        pref = context.getSharedPreferences("MyPref", 0); // 0 - for private mode
    }

    public void setLocalRegistrationId(int id) {
        SharedPreferences.Editor editor = pref.edit();
        editor.putInt("registrationId", id);
        editor.commit();
    }
    public int getLocalRegistrationId() {
        return pref.getInt("registrationId", -1);
    }
    public void setIdentityKeyPair(IdentityKeyPair identityKeyPair) {
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("identityKeyPair", Base64.encodeToString(identityKeyPair.serialize(), Base64.NO_WRAP));
        editor.commit();
    }
    public IdentityKeyPair getIdentityKeyPair() {
        String identityKeyPairString = pref.getString("identityKeyPair", null);
        IdentityKeyPair identityKeyPair = null;
        if (identityKeyPairString == null) {
            return identityKeyPair;
        }
        try {
            identityKeyPair = new IdentityKeyPair(Base64.decode(identityKeyPairString, Base64.NO_WRAP));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return identityKeyPair;
    }
    public void storeCurve25519KeyPair(String publicKey, String privateKey) {
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("curve25519PublicKey", publicKey);
        editor.putString("curve25519PrivateKey", privateKey);
        editor.commit();
    }
    public WritableMap loadCurve25519KeyPair() {
        String publicKey = pref.getString("curve25519PublicKey", null);
        String privateKey = pref.getString("curve25519PrivateKey", null);
        WritableMap keyPairMap = Arguments.createMap();
        keyPairMap.putString("publicKey", publicKey);
        keyPairMap.putString("privateKey", privateKey);
        return keyPairMap;
    }

    public void storeEd25519OctetKeyPair(String keyPairJSONString) {
        SharedPreferences.Editor editor = pref.edit();
        editor.putString("Ed25519OKeyPairJSONString", keyPairJSONString);
        editor.commit();
    }
    public String loadEd25519OctetKeyPair() {
        String keyPairJSONString = pref.getString("Ed25519OKeyPairJSONString", null);
        return keyPairJSONString;
    }
}
