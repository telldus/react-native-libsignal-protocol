package com.reactlibrary.axolotl;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
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

import com.facebook.react.bridge.WritableMap;
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

    public void buildSession(String recipientId, ArrayList<ReadableMap> deviceListWithBundle) throws InvalidKeyException, UntrustedIdentityException {
        for (int i = 0; i < deviceListWithBundle.size(); i++) {
            ReadableMap rm = deviceListWithBundle.get(i);
            int deviceId = rm.getInt("deviceId");
            ReadableMap bundle = rm.getMap("bundle");
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);

            // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
            SessionBuilder sessionBuilder = new SessionBuilder(protocolStore, signalProtocolAddress);

            int preKeyId = bundle.getInt("preKeyId");
            int registrationId = bundle.getInt("registrationId");
            ECPublicKey preKey = Curve.decodePoint(Base64.decode(bundle.getString("preKeyPublic"), Base64.NO_WRAP), 0);
            int signedPreKeyId = bundle.getInt("signedPreKeyId");
            ECPublicKey signedPreKeyPublic = Curve.decodePoint(Base64.decode(bundle.getString("signedPreKeyPublic"), Base64.NO_WRAP), 0);
            byte[] signedPreKeySignature = Base64.decode(bundle.getString("signedPreKeySignature"), Base64.NO_WRAP);
            IdentityKey identityKey = new IdentityKey(Base64.decode(bundle.getString("identityKey"), Base64.NO_WRAP), 0);

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
    }

    public String encrypt (String message, String recipientId, int deviceId) throws UntrustedIdentityException, UnsupportedEncodingException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);
        SessionCipher sessionCipher = new SessionCipher(protocolStore, signalProtocolAddress);
        CiphertextMessage messageEncryped = sessionCipher.encrypt(message.getBytes("UTF-8"));
        return Base64.encodeToString(messageEncryped.serialize(), Base64.NO_WRAP);
    }
    public WritableMap encryptTwo (String ownId, int ownDeviceId, String recipientId, ArrayList<Integer> deviceList, String message) throws CryptoFailedException {

        XmppAxolotlMessage xmppAxolotlMessage = new XmppAxolotlMessage(ownId, ownDeviceId);
        xmppAxolotlMessage.encrypt(message);
        XmppAxolotlSession remoteSessions = null;
        for (int i = 0; i < deviceList.size(); i++) {
            SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceList.get(i));
            remoteSessions = new XmppAxolotlSession(protocolStore, signalProtocolAddress);
            xmppAxolotlMessage.addDevice(remoteSessions);
        }
        return xmppAxolotlMessage.getAllData();
    }
    public String decryptTwo (String senderId, int deviceId, byte[] iV, ArrayList<XmppAxolotlSession.AxolotlKey> keysList, byte[] cipherText) throws CryptoFailedException, NotEncryptedForThisDeviceException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(senderId, deviceId);
        XmppAxolotlMessage xmppAxolotlMessage = new XmppAxolotlMessage(senderId, deviceId, iV, keysList, cipherText);
        return xmppAxolotlMessage.decrypt(new XmppAxolotlSession(protocolStore, signalProtocolAddress), deviceId);
    }
    public String decrypt (String message, String recipientId, int deviceId) throws InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, UntrustedIdentityException, LegacyMessageException {
        SignalProtocolAddress signalProtocolAddress = new SignalProtocolAddress(recipientId, deviceId);
        SessionCipher sessionCipher = new SessionCipher(protocolStore, signalProtocolAddress);
        byte[] messageDecrypted = null;
        messageDecrypted = sessionCipher.decrypt(new PreKeySignalMessage(Base64.decode(message, Base64.NO_WRAP)));
        return new String (messageDecrypted);
    }
}
