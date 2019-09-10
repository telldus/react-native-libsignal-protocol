
package com.reactlibrary;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;

import com.reactlibrary.axolotl.CryptoFailedException;
import com.reactlibrary.axolotl.NotEncryptedForThisDeviceException;
import com.reactlibrary.axolotl.XmppAxolotlSession;
import com.reactlibrary.storage.ProtocolStorage;
import com.reactlibrary.axolotl.XmppAxolotlService;
import com.reactlibrary.storage.PreferenceManager;


import android.util.Log;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.lang.Exception;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.whispersystems.curve25519.Curve25519.BEST;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;
import com.nimbusds.jwt.*;

import net.minidev.json.JSONObject;


public class RNOMEMOCipherModule extends ReactContextBaseJavaModule {

  private final ReactApplicationContext reactContext;
  public static final String RN_OMEMO_CIPHER_ERROR = "RN_OMEMO_CIPHER_ERROR";

  private ProtocolStorage protocolStorage;
  private XmppAxolotlService xmppAxolotlService;

  public RNOMEMOCipherModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;

    protocolStorage = new ProtocolStorage(reactContext);
    xmppAxolotlService =  new XmppAxolotlService(reactContext, protocolStorage);
  }

  @Override
  public String getName() {
    return "RNOMEMOCipher";
  }

  /**
   * libsignal
   */

  @ReactMethod
  public void generateIdentityKeyPair(Promise promise) {
    try {
      IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
      protocolStorage.setIdentityKeyPair(identityKeyPair);
      promise.resolve(prepareIKP(identityKeyPair));

    } catch (Exception e) {
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  private WritableMap prepareIKP(IdentityKeyPair identityKeyPair) {
    String publicKey = Base64.encodeToString(identityKeyPair.getPublicKey().serialize(), Base64.NO_WRAP);
    String privateKey = Base64.encodeToString(identityKeyPair.getPrivateKey().serialize(), Base64.NO_WRAP);
    String serializedKP = Base64.encodeToString(identityKeyPair.serialize(), Base64.NO_WRAP);
    WritableMap keyPairMap = Arguments.createMap();
    keyPairMap.putString("publicKey", publicKey);
    keyPairMap.putString("privateKey", privateKey);
    keyPairMap.putString("serializedKP", serializedKP);
    return keyPairMap;
  }

  @ReactMethod
  public void generateRegistrationId(Promise promise) {
    try {
      int registrationId = KeyHelper.generateRegistrationId(false);
      protocolStorage.setLocalRegistrationId(registrationId);
      promise.resolve(registrationId);
    } catch (Exception e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void generatePreKeys(int startId, int count, Promise promise) {
    try {
      List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, count);

      WritableArray preKeyMapsArray = Arguments.createArray();
      for (PreKeyRecord key : preKeys) {
        String preKeyPublic = Base64.encodeToString(key.getKeyPair().getPublicKey().serialize(), Base64.NO_WRAP);
        String preKeyPrivate = Base64.encodeToString(key.getKeyPair().getPrivateKey().serialize(), Base64.NO_WRAP);
        int preKeyId = key.getId();
        String seriaizedPreKey = Base64.encodeToString(key.serialize(), Base64.NO_WRAP);
        WritableMap preKeyMap = Arguments.createMap();
        preKeyMap.putString("preKeyPublic", preKeyPublic);
        preKeyMap.putString("preKeyPrivate", preKeyPrivate);
        preKeyMap.putInt("preKeyId", preKeyId);
        preKeyMap.putString("seriaizedPreKey", seriaizedPreKey);
        preKeyMapsArray.pushMap(preKeyMap);

        protocolStorage.storePreKey(preKeyId, key);
      }

      promise.resolve(preKeyMapsArray);
    } catch (Exception e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void generateSignedPreKey(ReadableMap identityKeyPair, int signedKeyId, Promise promise) {
    try {
      byte[] serialized = Base64.decode(identityKeyPair.getString("serializedKP"), Base64.NO_WRAP);

      IdentityKeyPair IKP = new IdentityKeyPair(serialized);
      SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(IKP, signedKeyId);
      int signedPreKeyId = signedPreKey.getId();

      protocolStorage.storeSignedPreKey(signedPreKeyId, signedPreKey);

      promise.resolve(prepareSignedPK(signedPreKey));
    } catch (Exception e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  private WritableMap prepareSignedPK(SignedPreKeyRecord signedPreKey) {
    String signedPreKeyPublic = Base64.encodeToString(signedPreKey.getKeyPair().getPublicKey().serialize(), Base64.NO_WRAP);
    String signedPreKeyPrivate = Base64.encodeToString(signedPreKey.getKeyPair().getPrivateKey().serialize(), Base64.NO_WRAP);
    String signedPreKeySignature = Base64.encodeToString(signedPreKey.getSignature(), Base64.NO_WRAP);
    int signedPreKeyId = signedPreKey.getId();
    String seriaizedSignedPreKey = Base64.encodeToString(signedPreKey.serialize(), Base64.NO_WRAP);

    WritableMap signedPreKeyMap = Arguments.createMap();
    signedPreKeyMap.putString("signedPreKeyPublic", signedPreKeyPublic);
    signedPreKeyMap.putString("signedPreKeyPrivate", signedPreKeyPrivate);
    signedPreKeyMap.putString("signedPreKeySignature", signedPreKeySignature);
    signedPreKeyMap.putInt("signedPreKeyId", signedPreKeyId);
    signedPreKeyMap.putString("seriaizedSignedPreKey", seriaizedSignedPreKey);
    return signedPreKeyMap;
  }

  @ReactMethod
  public void buildSession(String recipientId, ReadableArray deviceListAndBundle, Promise promise) {
    try {
      ArrayList<ReadableMap> deviceListWithBundle = new ArrayList<ReadableMap>();
      for (int i = 0; i < deviceListAndBundle.size(); i++) {
        ReadableMap rm = deviceListAndBundle.getMap(i);
        WritableMap infoMapNew = Arguments.createMap();
        WritableMap empty = Arguments.createMap();
        empty.merge(rm.getMap("bundle"));
        infoMapNew.putString("deviceId", rm.getString("deviceId"));
        infoMapNew.putMap("bundle", empty);
        deviceListWithBundle.add(infoMapNew);
      }
      xmppAxolotlService.buildSession(recipientId, deviceListWithBundle);
      promise.resolve(true);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (UntrustedIdentityException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void encryptSignalProtocol(String message, String recipientId, int deviceId, Promise promise) {
    try {
      promise.resolve(xmppAxolotlService.encrypt(message, recipientId, deviceId));
    } catch (UntrustedIdentityException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void decryptSignalProtocol(String message, String recipientId, int deviceId, Promise promise) {
    try {
      promise.resolve(xmppAxolotlService.decrypt(message, recipientId, deviceId));
    } catch (UntrustedIdentityException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (LegacyMessageException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (InvalidMessageException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (DuplicateMessageException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (InvalidVersionException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (InvalidKeyIdException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }


  /**
   * OMEMO
   */

  @ReactMethod
  public void encryptOMEMO(String ownId, String ownDeviceId, String recipientId, ReadableArray deviceList, String message, Promise promise) {
    try {
      ArrayList<String> deviceIds = new ArrayList<String>();
      for (int i = 0; i < deviceList.size(); i++) {
        deviceIds.add(deviceList.getString(i));
      }
      promise.resolve(xmppAxolotlService.encryptOMEMO(ownId, ownDeviceId, recipientId, deviceIds, message));
    } catch (CryptoFailedException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void decryptOMEMO(String recipientId, String ownDeviceId, String iV, ReadableArray keysList, String cipherText, Promise promise) {
    try {
      ArrayList keys = new ArrayList<>();
      for (int i = 0; i < keysList.size(); i++) {
        ReadableMap axKeys = keysList.getMap(i);
        keys.add(new XmppAxolotlSession.AxolotlKey(axKeys.getString("deviceId"), Base64.decode(axKeys.getString("key"), Base64.NO_WRAP), axKeys.getBoolean("prekey")));
      }
      promise.resolve(xmppAxolotlService.decryptOMEMO(recipientId, ownDeviceId, Base64.decode(iV, Base64.NO_WRAP), keys, Base64.decode(cipherText, Base64.NO_WRAP)));
    } catch (CryptoFailedException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (NotEncryptedForThisDeviceException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (AssertionError e) {
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }


  /**
   * Curve25519
   */

  @ReactMethod
  public void generateCurve25519KeyPair(Promise promise) {
    Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();
    WritableMap keyPairMap = Arguments.createMap();
    String publicKey = Base64.encodeToString(keyPair.getPublicKey(), Base64.NO_WRAP);
    String privateKey = Base64.encodeToString(keyPair.getPrivateKey(), Base64.NO_WRAP);
    keyPairMap.putString("publicKey", publicKey);
    keyPairMap.putString("privateKey", privateKey);
    promise.resolve(keyPairMap);
  }

  @ReactMethod
  public void storeCurve25519KeyPair(String publicKey, String privateKey, Promise promise) {
    PreferenceManager preferenceManager = new PreferenceManager(reactContext);
    preferenceManager.storeCurve25519KeyPair(publicKey, privateKey);
    promise.resolve(true);
  }

  @ReactMethod
  public void loadCurve25519KeyPair(Promise promise) {
    PreferenceManager preferenceManager = new PreferenceManager(reactContext);
    promise.resolve(preferenceManager.loadCurve25519KeyPair());
  }


  /**
   * Ed25519OctetKeyPair
   */

  @ReactMethod
  public void generateEd25519OctetKeyPair(Promise promise) {
    try {
      promise.resolve(generateKP());
    } catch (JOSEException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void storeEd25519OctetKeyPair(String keyPairJSONString, Promise promise) {
    PreferenceManager preferenceManager = new PreferenceManager(reactContext);
    preferenceManager.storeEd25519OctetKeyPair(keyPairJSONString);
    promise.resolve(true);
  }

  /**
   * Returns stored keypair if available in the pref manager, if not generates new one.
   */
  @ReactMethod
  public void loadEd25519OctetKeyPair(Promise promise) {
    PreferenceManager preferenceManager = new PreferenceManager(reactContext);
    String kP = preferenceManager.loadEd25519OctetKeyPair();
    if (kP != null) {
      OctetKeyPair jwk = createOctetKeyPairFromJSONString(kP);
      promise.resolve(prepareJWK(jwk));
    } else {
      try {
        ReadableMap genKPMap = generateKP();
        preferenceManager.storeEd25519OctetKeyPair(genKPMap.getString("keyPairJSONString"));
        promise.resolve(genKPMap);
      } catch (JOSEException e) {
        e.printStackTrace();
        promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
      }
    }
  }

  @ReactMethod
  public void createJWTFromEd25519OctetKeyPair(
          String subject,
          String issuer,
          String expirationTimeStamp,
          String issueTime,
          String claimName,
          String claimValue,
          String keyPairJSONString,
          Promise promise) {
    // Generate a key pair with Ed25519 curve
    OctetKeyPair jwk = null;
    try {
      Date expirationTimeN = new Date((long) Long.parseLong(expirationTimeStamp));
      Date issueTimeN = new Date((long) Long.parseLong(issueTime));
      jwk = createOctetKeyPairFromJSONString(keyPairJSONString);

      // Create the EdDSA signer
      JWSSigner signer = new Ed25519Signer(jwk);

      // Prepare JWT with claims set
      JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
              .subject(subject)
              .issuer(issuer)
              .expirationTime(expirationTimeN)
              .claim(claimName, claimValue)
              .issueTime(issueTimeN)
              .build();

      SignedJWT signedJWT = new SignedJWT(
              new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
              claimsSet);

      // Compute the EC signature
      signedJWT.sign(signer);

      // Serialize the JWS to compact form
      String jwt = signedJWT.serialize();

      WritableMap dataMap = Arguments.createMap();
      dataMap.putString("jwt", jwt);
      promise.resolve(dataMap);
    } catch (JOSEException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  @ReactMethod
  public void verifyJWT(String jwt, OctetKeyPair publicJWK, String claimName, String claimValue, Promise promise) {
    OctetKeyPair jwk = null;
    try {
      SignedJWT signedJWT = SignedJWT.parse(jwt);
      JWSVerifier verifier = new Ed25519Verifier(publicJWK);

      WritableMap verificationStatus = Arguments.createMap();
      if(signedJWT.verify(verifier)) {
        JWTClaimsSet jwtCS = signedJWT.getJWTClaimsSet();
        String claimValueReceived = (String) jwtCS.getClaim(claimName);
        if (claimValueReceived == claimValue) {
          verificationStatus.putBoolean("verified", true);
          promise.resolve(verificationStatus);
        } else {
          verificationStatus.putBoolean("verified", false);
          promise.resolve(verificationStatus);
        }
      } else {
        verificationStatus.putBoolean("verified", false);
        promise.resolve(verificationStatus);
      }
    } catch (JOSEException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    } catch (ParseException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }

  private OctetKeyPair createOctetKeyPairFromJSONString(String keyPairJSONString) {
    OctetKeyPair octetKeyPair = null;
    try {
      return  OctetKeyPair.parse(keyPairJSONString);
    } catch (ParseException e) {
      e.printStackTrace();
    }
    return octetKeyPair;
  }

  private WritableMap generateKP() throws JOSEException {
      OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
              .keyID("123")
              .generate();
    return prepareJWK(jwk);
  }

  private WritableMap prepareJWK(OctetKeyPair jwk) {
    WritableMap dataMap = Arguments.createMap();
    dataMap.putString("keyPairJSONString", jwk.toJSONString());
    dataMap.putString("publicJWKString", jwk.toPublicJWK().toJSONString());
    return dataMap;
  }


  /**
   * libsignal utilities
   */

  /**
   *
   * This can be used to get the latest prekeys set
   * may be after decrypt, and update the user's bundle info.
   * (becuse after decryption the used prekey is removed)
   */
  @ReactMethod
  public void loadPreKeys(Promise promise) {
    List<PreKeyRecord> preKeys = protocolStorage.loadPreKeys();

    WritableArray preKeyMapsArray = Arguments.createArray();
    for (PreKeyRecord key : preKeys) {
      String preKeyPublic = Base64.encodeToString(key.getKeyPair().getPublicKey().serialize(), Base64.NO_WRAP);
      String preKeyPrivate = Base64.encodeToString(key.getKeyPair().getPrivateKey().serialize(), Base64.NO_WRAP);
      int preKeyId = key.getId();
      String seriaizedPreKey = Base64.encodeToString(key.serialize(), Base64.NO_WRAP);
      WritableMap preKeyMap = Arguments.createMap();
      preKeyMap.putString("preKeyPublic", preKeyPublic);
      preKeyMap.putString("preKeyPrivate", preKeyPrivate);
      preKeyMap.putInt("preKeyId", preKeyId);
      preKeyMap.putString("seriaizedPreKey", seriaizedPreKey);
      preKeyMapsArray.pushMap(preKeyMap);
    }
    promise.resolve(preKeyMapsArray);
  }

  @ReactMethod
  public void loadIdentityKeyPair(Promise promise) {
    IdentityKeyPair identityKeyPair = protocolStorage.getIdentityKeyPair();
    if (identityKeyPair == null) {
      promise.resolve(identityKeyPair);
    } else {
      promise.resolve(prepareIKP(identityKeyPair));
    }
  }

  @ReactMethod
  public void loadRegistrationId(Promise promise) {
    promise.resolve(protocolStorage.getLocalRegistrationId());
  }

  @ReactMethod
  public void loadSignedPreKey(int signedPreKeyId, Promise promise) {
    try {
      SignedPreKeyRecord signedPreKeyRecord = protocolStorage.loadSignedPreKey(signedPreKeyId);
      if (signedPreKeyRecord == null) {
        promise.resolve(signedPreKeyRecord);
      } else {
        promise.resolve(prepareSignedPK(signedPreKeyRecord));
      }
    } catch (InvalidKeyIdException e) {
      e.printStackTrace();
      promise.reject(RN_OMEMO_CIPHER_ERROR, e.getMessage());
    }
  }
}