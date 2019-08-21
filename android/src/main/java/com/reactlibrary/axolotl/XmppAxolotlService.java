package com.reactlibrary.axolotl;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;

import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import com.reactlibrary.RNLibsignalProtocolModule;
import com.reactlibrary.storage.ProtocolStorage;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

public class XmppAxolotlService {
    ProtocolStorage protocolStore;
    private final ReactApplicationContext reactContext;
    public XmppAxolotlService(ReactApplicationContext context, ProtocolStorage protocolStorage) {
        protocolStore = protocolStorage;
        reactContext = context;
    }

    public void buildSession(String recipientId, int deviceId, ReadableMap retrievedPreKeyBundle) throws InvalidKeyException, UntrustedIdentityException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);

        // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
        SessionBuilder sessionBuilder = new SessionBuilder(protocolStore, signalProtocolAddress);

            int preKeyId = retrievedPreKeyBundle.getInt("preKeyId");
            int registrationId = retrievedPreKeyBundle.getInt("registrationId");
            ECPublicKey preKey = Curve.decodePoint(Base64.decode(retrievedPreKeyBundle.getString("preKeyPublic"), Base64.DEFAULT), 0);
            int signedPreKeyId = retrievedPreKeyBundle.getInt("signedPreKeyId");
            ECPublicKey signedPreKeyPublic = Curve.decodePoint(Base64.decode(retrievedPreKeyBundle.getString("signedPreKeyPublic"), Base64.DEFAULT), 0);
            byte[] signedPreKeySignature = Base64.decode(retrievedPreKeyBundle.getString("signedPreKeySignature"), Base64.DEFAULT);
            IdentityKey identityKey = new IdentityKey(Base64.decode(retrievedPreKeyBundle.getString("identityKey"), Base64.DEFAULT), 0);

            PreKeyBundle preKeyBundle = new PreKeyBundle(
                    registrationId,
                    deviceId,
                    preKeyId,
                    preKey,
                    signedPreKeyId,
                    signedPreKeyPublic,
                    signedPreKeySignature,
                    identityKey
            );
            // Build a session with a PreKey retrieved from the server.
            sessionBuilder.process(preKeyBundle);
    }

    public String encrypt (String message, String recipientId, int deviceId) throws UntrustedIdentityException, UnsupportedEncodingException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);
        SessionCipher sessionCipher = new SessionCipher(protocolStore, signalProtocolAddress);
        CiphertextMessage messageEncryped = sessionCipher.encrypt(message.getBytes("UTF-8"));
        return Base64.encodeToString(messageEncryped.serialize(), Base64.DEFAULT);
    }
    public void encryptTwo (String message, String recipientId, int deviceId) throws CryptoFailedException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);
        XmppAxolotlMessage xmppAxolotlMessage = new XmppAxolotlMessage(recipientId, deviceId);
        xmppAxolotlMessage.encrypt(message);
        xmppAxolotlMessage.addDevice(new XmppAxolotlSession(protocolStore, signalProtocolAddress));
//        Log.d("TEST from", xmppAxolotlMessage.from);
//        Log.d("TEST sourceDeviceId", String.valueOf(xmppAxolotlMessage.sourceDeviceId));
//        for (int i = 0; i < xmppAxolotlMessage.keys.size(); i++) {
//            XmppAxolotlSession.AxolotlKey akey = xmppAxolotlMessage.keys.get(i);
//            Log.d("TEST deviceId", String.valueOf(akey.deviceId));
//            Log.d("TEST prekey", String.valueOf(akey.prekey));
//            Log.d("TEST key", String.valueOf(akey.key));
//        }
//        Log.d("TEST innerKey", String.valueOf(xmppAxolotlMessage.innerKey));
//        Log.d("TEST iv", String.valueOf(xmppAxolotlMessage.iv));
//        Log.d("TEST ciphertext", String.valueOf(xmppAxolotlMessage.ciphertext));
//        Log.d("TEST authtagPlusInn", String.valueOf(xmppAxolotlMessage.authtagPlusInnerKey));
    }
    public String decryptTwo (String senderId, int deviceId, byte[] iV, ArrayList<XmppAxolotlSession.AxolotlKey> keysList, byte[] cipherText) throws CryptoFailedException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, deviceId);
        XmppAxolotlMessage xmppAxolotlMessage = new XmppAxolotlMessage(senderId, deviceId, iV, keysList, cipherText);
        return xmppAxolotlMessage.decrypt(new XmppAxolotlSession(protocolStore, signalProtocolAddress), deviceId);
    }
    public String decrypt (String message, String recipientId, int deviceId) throws InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, UntrustedIdentityException, LegacyMessageException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);
        SessionCipher sessionCipher = new SessionCipher(protocolStore, signalProtocolAddress);
        byte[] messageDecrypted = null;
        messageDecrypted = sessionCipher.decrypt(new PreKeySignalMessage(Base64.decode(message, Base64.DEFAULT)));
        return new String (messageDecrypted);
    }
}
