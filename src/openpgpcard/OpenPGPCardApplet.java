package openpgpcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class OpenPGPCardApplet extends Applet {

  private static final byte[] historicalBytes = {
    0x00,
    0x73, (byte)0x80, 0x00, 0x00,  // Capabilities
    0x00, (byte)0x90, 0x00         // Status indicator
  };

  private static final byte[] extendedCap = {
    0x7C,
    0x01,  // AES
    0x00, (byte)0xFF,  // Maximum GET CHALLENGE size
    0x10, 0x00,  // Maximum certificate size
    0x00, (byte)0xFF,  // Maximum length of command data
    0x00, (byte)0xFF   // Maximum length of response data
  };

  private OwnerPIN pw1;
  private byte pw1Length;
  private OwnerPIN pw3;
  private byte pw3Length;
  private OwnerPIN rc;
  private byte rcLength;

  private boolean[] pinVerified;

  private static final byte[] DEFAULT_PW1 =
    { '1', '2', '3', '4', '5', '6', (byte)0xFF, (byte)0xFF };
  private static final byte[] DEFAULT_PW3 =
    { '1', '2', '3', '4', '5', '6', '7', '8' };

  private byte[] name;
  private byte[] languagePrefs;
  private byte[] url;
  private byte sex = OpenPGPCard.ISO5218_NOT_APPLICABLE;
  private byte[] loginData;

  private byte[] privateDO1;
  private byte[] privateDO2;
  private byte[] privateDO3;
  private byte[] privateDO4;

  private boolean forceSignaturePIN = true;
  private byte signatureCounterHigh = (byte)0;
  private short signatureCounterLow = (short)0;
  private byte[] certificate;
  private short certificateLength = (short)0;

  private byte[] outputChainingBuffer;
  private short outputChainingLength = (short)0;
  private short outputChainingSent = (short)0;

  private Cipher cipher;
  private RandomData randomGen;

  private KeyPair signKey;
  private short signKeyBits = 2048;
  private byte[] signKeyFingerprint;
  private byte[] signKeyGenerationTime;

  private KeyPair decryptKey;
  private short decryptKeyBits = 2048;
  private byte[] decryptKeyFingerprint;
  private byte[] decryptKeyGenerationTime;

  private KeyPair authKey;
  private short authKeyBits = 2048;
  private byte[] authKeyFingerprint;
  private byte[] authKeyGenerationTime;

  private byte[] ca1Fingerprint;
  private byte[] ca2Fingerprint;
  private byte[] ca3Fingerprint;

  private byte[] keyReturnBuffer;

  private byte[] authBuffer;

  private OpenPGPCardApplet() {
    pw1 = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    pw1.update(DEFAULT_PW1, (short)0, (byte)DEFAULT_PW1.length);
    pw1Length = (byte)DEFAULT_PW1.length;

    pw3 = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    pw3.update(DEFAULT_PW3, (short)0, (byte)DEFAULT_PW3.length);
    pw3Length = (byte)DEFAULT_PW3.length;

    rc = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    rcLength = (byte)0;

    pinVerified = JCSystem.makeTransientBooleanArray(
      (short)2, JCSystem.CLEAR_ON_DESELECT);
    keyReturnBuffer = JCSystem.makeTransientByteArray(
      (short)516, JCSystem.CLEAR_ON_DESELECT);

    name = new byte[OpenPGPCard.NAME_SIZE];
    languagePrefs = new byte[OpenPGPCard.LANGUAGE_PREFS_SIZE];
    url = new byte[OpenPGPCard.URL_SIZE];
    loginData = new byte[OpenPGPCard.LOGIN_DATA_SIZE];
    byte loginData_length = 0;

    // hax to get GPG to recognize the card as supporting PIN entry
    loginData[loginData_length++] = (byte)7;
    loginData[loginData_length++] = '\n';
    loginData[loginData_length++] = 0x14;
    loginData[loginData_length++] = 'P';
    loginData[loginData_length++] = '=';
    loginData[loginData_length++] = '8';
    loginData[loginData_length++] = ',';
    loginData[loginData_length++] = '8';

    privateDO1 = new byte[OpenPGPCard.PRIVATE_DO_SIZE];
    privateDO2 = new byte[OpenPGPCard.PRIVATE_DO_SIZE];
    privateDO3 = new byte[OpenPGPCard.PRIVATE_DO_SIZE];
    privateDO4 = new byte[OpenPGPCard.PRIVATE_DO_SIZE];

    signKey = new KeyPair(KeyPair.ALG_RSA_CRT, signKeyBits);
    decryptKey = new KeyPair(KeyPair.ALG_RSA_CRT, decryptKeyBits);
    authKey = new KeyPair(KeyPair.ALG_RSA_CRT, authKeyBits);

    signKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    decryptKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    authKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];

    signKeyGenerationTime = new byte[OpenPGPCard.TIMESTAMP_SIZE];
    decryptKeyGenerationTime = new byte[OpenPGPCard.TIMESTAMP_SIZE];
    authKeyGenerationTime = new byte[OpenPGPCard.TIMESTAMP_SIZE];

    ca1Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    ca2Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    ca3Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];

    certificate = new byte[OpenPGPCard.CERTIFICATE_SIZE];

    cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
    randomGen = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    authBuffer = new byte[OpenPGPCard.AUTH_BUFFER_SIZE];
  }

  public static void install(
    byte[] bArray, short bOffset, byte bLength) throws ISOException {
    new OpenPGPCardApplet().register(
      bArray, (short)(1 + bOffset), bArray[bOffset]
    );
  }

  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      return;
    }
    byte[] buffer = apdu.getBuffer();
    byte cla = buffer[ISO7816.OFFSET_CLA];
    byte ins = buffer[ISO7816.OFFSET_INS];
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short p1p2 = Util.makeShort(p1, p2);

    short le = 0;

    if (ins != OpenPGPCard.CMD_GET_RESPONSE) {
      outputChainingSent = outputChainingLength = (short)0;
    }

    switch (ins) {
      case OpenPGPCard.CMD_GET_RESPONSE:
        le = getResponse(apdu);
        break;
      case OpenPGPCard.CMD_VERIFY:
        verify(apdu);
        break;
      case OpenPGPCard.CMD_CHANGE_REFERENCE_DATA:
        changeReferenceData(apdu);
        break;
      case OpenPGPCard.CMD_RESET_RETRY_COUNTER:
        resetRetryCounter(apdu);
        break;
      case OpenPGPCard.CMD_GET_CHALLENGE:
        le = getChallenge(apdu);
        break;
      case OpenPGPCard.CMD_GET_DATA:
        le = getData(apdu);
        break;
      case OpenPGPCard.CMD_PUT_DATA:
        putData(apdu);
        break;
      case OpenPGPCard.CMD_GENERATE_ASYMMETRIC_KEY_PAIR:
        le = generateKey(apdu);
        break;
      case OpenPGPCard.CMD_PERFORM_SECURITY_OPERATION:
        if (p1p2 == OpenPGPCard.PSO_SIGNATURE) {
          le = computeSignature(apdu);
        } else if (p1p2 == OpenPGPCard.PSO_DECIPHER) {
          le = decipher(apdu);
        }
        break;
      case OpenPGPCard.CMD_INTERNAL_AUTHENTICATE:
        le = internalAuthenticate(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    if (le > (short)0) {
      apdu.setOutgoingAndSend((short)0, le);
      if (outputChainingSent < outputChainingLength) {
        short left = (short)(outputChainingLength - outputChainingSent);
        if (left > 0xFF) {
          left = 0xFF;
        }
        ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 | left));
      }
    }
  }

  private short getResponse(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short le = (short)(outputChainingLength - outputChainingSent);

    invariant(p1 == (byte)0 && p2 == (byte)0, ISO7816.SW_INCORRECT_P1P2);
    if (le > 0xFF) {
      le = 0xFF;
    }
    outputChainingSent += Util.arrayCopyNonAtomic(
      outputChainingBuffer, outputChainingSent,
      buffer, (short)0,
      le
    );
    return le;
  }

  private void verify(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    byte lc = buffer[ISO7816.OFFSET_LC];

    invariant(
      p1 == (byte)0 &&
      (p2 == (byte)0x81 || p2 == (byte)0x82 || p2 == (byte)0x83),
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);

    if (p2 == (byte)0x81 || p2 == (byte)0x82) {
      if (!pw1.check(buffer, ISO7816.OFFSET_CDATA, lc)) {
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw1.getTriesRemaining()));
      }
      pinVerified[(byte)(p2 - (byte)0x81)] = true;
    } else if (p2 == (byte)0x83) {
      if (!pw3.check(buffer, ISO7816.OFFSET_CDATA, lc)) {
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw3.getTriesRemaining()));
      }
    }
  }

  private void changeReferenceData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
    byte new_length;

    invariant(
      p1 == (byte)0 && (p2 == (byte)0x81 || p2 == (byte)0x83),
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);

    if (p2 == (byte)0x81) {
      if (!pw1.check(buffer, ISO7816.OFFSET_CDATA, (byte)lc)) {
        pinVerified[0] = false;
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw1.getTriesRemaining()));
      }
      new_length = (byte)(lc - pw1Length);
      invariant(
        OpenPGPCard.MIN_PIN_LENGTH <= new_length &&
        new_length <= OpenPGPCard.MAX_PIN_LENGTH,
        ISO7816.SW_WRONG_LENGTH
      );

      JCSystem.beginTransaction();
      pw1.update(
        buffer, (short)(ISO7816.OFFSET_CDATA + pw1Length), new_length);
      pw1Length = new_length;
      JCSystem.commitTransaction();
      pinVerified[0] = pinVerified[1] = false;
    } else if (p2 == (byte)0x83) {
      if (!pw3.check(buffer, ISO7816.OFFSET_CDATA, (byte)lc)) {
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw3.getTriesRemaining()));
      }
      new_length = (byte)(lc - pw3Length);
      invariant(
        (byte)OpenPGPCard.MIN_PIN_LENGTH <= new_length &&
        new_length <= (byte)OpenPGPCard.MAX_PIN_LENGTH,
        ISO7816.SW_WRONG_LENGTH
      );

      JCSystem.beginTransaction();
      pw3.update(
        buffer, (short)(ISO7816.OFFSET_CDATA + pw3Length), new_length);
      pw3Length = new_length;
      JCSystem.commitTransaction();
    }
  }

  private void resetRetryCounter(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
    byte new_length;

    invariant(p2 == (byte)0x81, ISO7816.SW_INCORRECT_P1P2);
    invariant(apdu.setIncomingAndReceive() == lc, ISO7816.SW_WRONG_LENGTH);
    if (p1 == (byte)0) {
      new_length = (byte)(lc - rcLength);
      if (new_length < (byte)OpenPGPCard.MIN_PIN_LENGTH ||
          new_length > (byte)OpenPGPCard.MAX_PIN_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      if (!rc.check(buffer, (short)0, rcLength)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      JCSystem.beginTransaction();
      pw1.update(buffer, (short)(ISO7816.OFFSET_CDATA + rcLength), new_length);
      pw1Length = new_length;
      JCSystem.commitTransaction();
      pinVerified[0] = pinVerified[1] = false;
    } else if (p1 == (byte)2) {
      invariant(pw3.isValidated(), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      if (lc < (byte)OpenPGPCard.MIN_PIN_LENGTH ||
          lc > (byte)OpenPGPCard.MAX_PIN_LENGTH) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
      JCSystem.beginTransaction();
      pw1.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)lc);
      pw1Length = (byte)lc;
      JCSystem.commitTransaction();
      pinVerified[0] = pinVerified[1] = false;
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  private short getData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short tag = Util.makeShort(
      buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
    short data_len = (short)0;
    short tmp_length;

    switch (tag) {
      case OpenPGPCard.DO_PRIVATE_1:
        return Util.arrayCopyNonAtomic(
          privateDO1, (short)1,
          buffer, (short)0,
          (short)(privateDO1[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_2:
        return Util.arrayCopyNonAtomic(
          privateDO2, (short)1,
          buffer, (short)0,
          (short)(privateDO2[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_3:
        return Util.arrayCopyNonAtomic(
          privateDO3, (short)1,
          buffer, (short)0,
          (short)(privateDO3[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_4:
        return Util.arrayCopyNonAtomic(
          privateDO4, (short)1,
          buffer, (short)0,
          (short)(privateDO4[0] & 0xFF)
        );
      case OpenPGPCard.DO_AID:
        return JCSystem.getAID().getBytes(buffer, (short)0);
      case OpenPGPCard.DO_LOGIN_DATA:
        return Util.arrayCopyNonAtomic(
          loginData, (short)1,
          buffer, (short)0,
          (short)(loginData[0] & 0xFF)
        );
      case OpenPGPCard.DO_URL:
        return Util.arrayCopyNonAtomic(
          url, (short)1,
          buffer, (short)0,
          (short)(url[0] & 0xFF)
        );
      case OpenPGPCard.DO_HISTORICAL_BYTES:
        return Util.arrayCopyNonAtomic(
          historicalBytes, (short)0,
          buffer, (short)0,
          (short)historicalBytes.length
        );
      case OpenPGPCard.DO_CARDHOLDER_DATA:  // TLV encoded
        // Header size = 2 bytes
        buffer[data_len++] = (byte)OpenPGPCard.DO_CARDHOLDER_DATA;
        buffer[data_len++] = (byte)0;  // placeholder for length

        buffer[data_len++] = (byte)OpenPGPCard.DO_NAME;
        data_len = Util.arrayCopyNonAtomic(
          name, (short)0, buffer, data_len, (short)(1 + name[0]));
        data_len = Util.setShort(buffer, data_len, OpenPGPCard.DO_LANGUAGE_PREFS);
        data_len = Util.arrayCopyNonAtomic(
          languagePrefs, (short)0,
          buffer, data_len,
          (short)(1 + languagePrefs[0])
        );
        data_len = Util.setShort(buffer, data_len, OpenPGPCard.DO_SEX);
        buffer[data_len++] = (byte)1;
        buffer[data_len++] = sex;
        buffer[(short)1] = (byte)(data_len - 2);
        return data_len;
      case OpenPGPCard.DO_APPLICATION_DATA:  // TLV encoded
        // Header size = 4 bytes
        buffer[data_len++] = (byte)OpenPGPCard.DO_APPLICATION_DATA;
        buffer[data_len++] = (byte)0x82;
        data_len = Util.setShort(buffer, data_len, (short)0);

        buffer[data_len++] = (byte)OpenPGPCard.DO_AID;
        tmp_length = data_len++;
        data_len = JCSystem.getAID().getBytes(buffer, data_len);
        buffer[tmp_length] = (byte)(data_len - tmp_length);

        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.DO_HISTORICAL_BYTES);
        buffer[data_len++] = (byte)historicalBytes.length;
        data_len = Util.arrayCopyNonAtomic(
          historicalBytes, (short)0,
          buffer, data_len,
          (short)historicalBytes.length
        );

        buffer[data_len++] = (byte)OpenPGPCard.DO_DISCRETIONARY_DOS;
        buffer[data_len++] = (byte)0x81;
        tmp_length = data_len++;
        buffer[data_len++] = (byte)OpenPGPCard.DO_EXTENDED_CAP;
        buffer[data_len++] = (byte)extendedCap.length;
        data_len = Util.arrayCopyNonAtomic(
          extendedCap, (short)0,
          buffer, data_len,
          (short)extendedCap.length
        );

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_SIGN;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(buffer, data_len, signKeyBits);
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.RSA_EXPONENT_BITS);
        buffer[data_len++] = OpenPGPCard.RSA_FORMAT_CRT_MODULUS;

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_DECRYPT;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(buffer, data_len, decryptKeyBits);
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.RSA_EXPONENT_BITS);
        buffer[data_len++] = OpenPGPCard.RSA_FORMAT_CRT_MODULUS;

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_AUTH;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(buffer, data_len, authKeyBits);
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.RSA_EXPONENT_BITS);
        buffer[data_len++] = OpenPGPCard.RSA_FORMAT_CRT_MODULUS;

        buffer[data_len++] = (byte)OpenPGPCard.DO_PW_STATUS;
        buffer[data_len++] = (byte)7;
        buffer[data_len++] = forceSignaturePIN ? (byte)0 : (byte)1;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = pw1.getTriesRemaining();
        buffer[data_len++] = rc.getTriesRemaining();
        buffer[data_len++] = pw3.getTriesRemaining();

        buffer[data_len++] = (byte)OpenPGPCard.DO_FINGERPRINTS;
        buffer[data_len++] = (byte)(3 * OpenPGPCard.FINGERPRINT_SIZE);
        data_len = Util.arrayCopyNonAtomic(
          signKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          decryptKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          authKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );

        buffer[data_len++] = (byte)OpenPGPCard.DO_CA_FINGERPRINTS;
        buffer[data_len++] = (byte)(3 * OpenPGPCard.FINGERPRINT_SIZE);
        data_len = Util.arrayCopyNonAtomic(
          ca1Fingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          ca2Fingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          ca3Fingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );

        buffer[data_len++] = (byte)OpenPGPCard.DO_GENERATION_TIMES;
        buffer[data_len++] = (byte)(3 * OpenPGPCard.TIMESTAMP_SIZE);
        data_len = Util.arrayCopyNonAtomic(
          signKeyGenerationTime, (short)0,
          buffer, data_len,
          OpenPGPCard.TIMESTAMP_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          decryptKeyGenerationTime, (short)0,
          buffer, data_len,
          OpenPGPCard.TIMESTAMP_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          authKeyGenerationTime, (short)0,
          buffer, data_len,
          OpenPGPCard.TIMESTAMP_SIZE
        );
        buffer[tmp_length] = (byte)(data_len - tmp_length);

        Util.setShort(buffer, (short)2, (short)(data_len - 4));
        return data_len;
      case OpenPGPCard.DO_PW_STATUS:
        buffer[data_len++] = forceSignaturePIN ? (byte)0 : (byte)1;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = OpenPGPCard.MAX_PIN_LENGTH;
        buffer[data_len++] = pw1.getTriesRemaining();
        buffer[data_len++] = rc.getTriesRemaining();
        buffer[data_len++] = pw3.getTriesRemaining();
        return data_len;
      case OpenPGPCard.DO_FINGERPRINTS:
        data_len = Util.arrayCopyNonAtomic(
          signKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          decryptKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          authKeyFingerprint, (short)0,
          buffer, data_len,
          OpenPGPCard.FINGERPRINT_SIZE
        );
        return data_len;
      case OpenPGPCard.DO_SECURITY_TEMPLATE:  // TLV encoded
        buffer[data_len++] = (byte)OpenPGPCard.DO_SECURITY_TEMPLATE;
        buffer[data_len++] = (byte)5;
        buffer[data_len++] = (byte)OpenPGPCard.DO_SIGNATURE_COUNTER;
        buffer[data_len++] = (byte)3;
        buffer[data_len++] = signatureCounterHigh;
        return Util.setShort(buffer, data_len, signatureCounterLow);
      case OpenPGPCard.DO_CERTIFICATE:  // TLV encoded
        data_len = Util.setShort(buffer, data_len, OpenPGPCard.DO_CERTIFICATE);
        if (certificateLength < (short)0x80) {
          buffer[data_len++] = (byte)certificateLength;
        } else if (certificateLength < (short)0x100) {
          buffer[data_len++] = (byte)0x81;
          buffer[data_len++] = (byte)certificateLength;
        } else {
          buffer[data_len++] = (byte)0x82;
          data_len = Util.setShort(buffer, data_len, certificateLength);
        }

        if ((short)(data_len + certificateLength) < (short)0x100) {
          return Util.arrayCopyNonAtomic(
            certificate, (short)0, buffer, data_len, certificateLength);
        } else {
          outputChainingBuffer = certificate;
          outputChainingLength = certificateLength;
          outputChainingSent = (short)(0xFF - data_len);
          return Util.arrayCopyNonAtomic(
            certificate, (short)0, buffer, data_len, outputChainingSent);
        }
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    return (short)0;
  }

  private void putData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short tag = Util.makeShort(
      buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

    invariant(apdu.setIncomingAndReceive() == lc, ISO7816.SW_WRONG_LENGTH);

    if (tag == OpenPGPCard.DO_PRIVATE_1 || tag == OpenPGPCard.DO_PRIVATE_3) {
      if (!pw1.isValidated() && !pinVerified[1]) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    } else if (!pw3.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    switch (tag) {
      case OpenPGPCard.DO_PRIVATE_1:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          privateDO1, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_2:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_3:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_4:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_NAME:
        invariant(lc < OpenPGPCard.NAME_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          name, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_LOGIN_DATA:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          name, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_LANGUAGE_PREFS:
        invariant(
          lc < OpenPGPCard.LANGUAGE_PREFS_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          languagePrefs, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_SEX:
        invariant(lc == (short)1, ISO7816.SW_WRONG_LENGTH);
        invariant(
          buffer[ISO7816.OFFSET_CDATA] == OpenPGPCard.ISO5218_MALE ||
          buffer[ISO7816.OFFSET_CDATA] == OpenPGPCard.ISO5218_FEMALE ||
          buffer[ISO7816.OFFSET_CDATA] == OpenPGPCard.ISO5218_NOT_APPLICABLE,
          ISO7816.SW_WRONG_DATA
        );
        sex = buffer[ISO7816.OFFSET_CDATA];
        break;
      case OpenPGPCard.DO_URL:
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          url, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_CERTIFICATE:

        break;
      case OpenPGPCard.DO_ALGORITHM_ATTR_SIGN:
        if (buffer[ISO7816.OFFSET_CDATA] != OpenPGPCard.ALGORITHM_ID_RSA ||
            Util.getShort(buffer, (short)ISO7816.OFFSET_CDATA) != OpenPGPCard.RSA_EXPONENT_BITS ||
            (buffer[(short)(ISO7816.OFFSET_CDATA + 5)] != (byte)1 &&
             buffer[(short)(ISO7816.OFFSET_CDATA + 5)] != (byte)3)) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        break;
      case OpenPGPCard.DO_ALGORITHM_ATTR_DECRYPT:
      case OpenPGPCard.DO_ALGORITHM_ATTR_AUTH:

      case OpenPGPCard.DO_PW_STATUS:
        invariant(lc == (short)1, (short)(ISO7816.SW_CORRECT_LENGTH_00 | 1));
        if (buffer[ISO7816.OFFSET_CDATA] == 0) {
          forceSignaturePIN = true;
        } else if (buffer[ISO7816.OFFSET_CDATA] == 1) {
          forceSignaturePIN = false;
        } else {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case OpenPGPCard.DO_FINGERPRINT_SIGN:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          signKeyFingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_FINGERPRINT_DECRYPT:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          decryptKeyFingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_FINGERPRINT_AUTH:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          authKeyFingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_FINGERPRINT_CA_1:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          ca1Fingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_FINGERPRINT_CA_2:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          ca2Fingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_FINGERPRINT_CA_3:
        invariant(
          lc == OpenPGPCard.FINGERPRINT_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.FINGERPRINT_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_LC,
          ca3Fingerprint, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_GENERATION_TIME_SIGN:
        invariant(
          lc == OpenPGPCard.TIMESTAMP_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.TIMESTAMP_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          signKeyGenerationTime, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_GENERATION_TIME_DECRYPT:
        invariant(
          lc == OpenPGPCard.TIMESTAMP_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.TIMESTAMP_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          decryptKeyGenerationTime, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_GENERATION_TIME_AUTH:
        invariant(
          lc == OpenPGPCard.TIMESTAMP_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.TIMESTAMP_SIZE)
        );
        Util.arrayCopy(
          buffer, (short)ISO7816.OFFSET_CDATA,
          authKeyGenerationTime, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_RESET_CODE:
        invariant(
          lc == (short)0 ||
          (OpenPGPCard.MIN_RC_LENGTH <= lc && lc <= OpenPGPCard.MAX_PIN_LENGTH),
          ISO7816.SW_WRONG_LENGTH
        );
        rc.update(buffer, (short)ISO7816.OFFSET_CDATA, (byte)lc);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  private short generateKey(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
    short data_len = (short)0;
    short param_len = (short)0;

    invariant(
      (p1 == (byte)0x80 || p1 == (byte)0x81) && p2 == (byte)0,
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);
    invariant(lc == (byte)2, (short)(ISO7816.SW_CORRECT_LENGTH_00 | 2));

    short crt = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
    KeyPair key = getKey(crt);

    if (p1 == (byte)0x80) {
      invariant(pw3.isValidated(), ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      JCSystem.beginTransaction();
      key.genKeyPair();
      if (crt == OpenPGPCard.CRT_SIGN_KEY) {
        signatureCounterHigh = (byte)0;
        signatureCounterLow = (short)0;
      }
      JCSystem.commitTransaction();
    }

    //invariant(key.getPublic().isInitialized(), ISO7816.SW_RECORD_NOT_FOUND);

    // Send back just the header and exponent in the first response, since
    // they are small. Return the key in subsequent GET_RESPONSE operations.

    // Header, length = 5
    data_len = Util.setShort(buffer, (short)0, (short)0x7F49);
    buffer[data_len++] = (byte)0x82;
    data_len += 2;  // placeholder for length at offset 3

    // Exponent block, length = 2 (1 header + 1 length) + exp_length
    buffer[data_len++] = (byte)0x82;
    short exp_length = ((RSAPublicKey)key.getPublic()).getExponent(
      buffer, (short)(1 + data_len));
    buffer[data_len] = (byte)exp_length;
    data_len += 1 + exp_length;

    // Key block, length = 4 (1 header + 3 length) + key_size
    keyReturnBuffer[0] = (byte)0x81;
    keyReturnBuffer[1] = (byte)0x82;
    short key_size =
      ((RSAPublicKey)key.getPublic()).getModulus(keyReturnBuffer, (short)4);
    Util.setShort(keyReturnBuffer, (short)2, key_size);
    outputChainingBuffer = keyReturnBuffer;
    outputChainingLength = (short)(4 + key_size);
    outputChainingSent = (short)0;

    Util.setShort(
      buffer, (short)3,
      (short)(2 + exp_length + outputChainingLength)
    );

    return data_len;
  }

  private short computeSignature(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);
    invariant(
      signKey.getPrivate().isInitialized(),
      ISO7816.SW_RECORD_NOT_FOUND
    );
    invariant(
      pw1.isValidated() || pinVerified[0],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );
    if (forceSignaturePIN) {
      pinVerified[0] = false;
    }

    cipher.init(signKey.getPrivate(), Cipher.MODE_ENCRYPT);
    short le = cipher.doFinal(
      buffer, ISO7816.OFFSET_CDATA, lc, outputChainingBuffer, (short)0);
    if (++signatureCounterLow == 0) {
      signatureCounterHigh++;
    }
    return Util.arrayCopyNonAtomic(
      outputChainingBuffer, (short)0, buffer, (short)0, le);
  }

  private short decipher(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);
    invariant(
      decryptKey.getPrivate().isInitialized(),
      ISO7816.SW_RECORD_NOT_FOUND
    );
    invariant(
      pw1.isValidated() || pinVerified[1],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );

    cipher.init(decryptKey.getPrivate(), Cipher.MODE_DECRYPT);
    short le = cipher.doFinal(
      buffer, ISO7816.OFFSET_CDATA, lc,
      outputChainingBuffer, (short)0
    );
    return Util.arrayCopyNonAtomic(
      outputChainingBuffer, (short)0,
      buffer, (short)0, le
    );
  }

  private KeyPair getKey(short crt) {
    switch (crt) {
      case OpenPGPCard.CRT_SIGN_KEY:
        return signKey;
      case OpenPGPCard.CRT_DECRYPT_KEY:
        return decryptKey;
      case OpenPGPCard.CRT_AUTH_KEY:
        return authKey;
    }
    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    return signKey;
  }

  private void invariant(boolean condition, short sw) {
    if (!condition) {
      ISOException.throwIt(sw);
    }
  }

  private short getChallenge(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short le = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

    invariant(p1 == (byte)0 && p2 == (byte)0, ISO7816.SW_INCORRECT_P1P2);
    if (le == 0) {
      le = (short)0xFF;
    }
    randomGen.generateData(buffer, (short)0, le);
    return le;
  }

  private short internalAuthenticate(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

    invariant(p1 == (byte)0 && p2 == (byte)0, ISO7816.SW_INCORRECT_P1P2);
    invariant(lc == apdu.setIncomingAndReceive(), ISO7816.SW_WRONG_LENGTH);
    invariant(
      lc <= 102, // = 0.4 * key size FIXME (make variable with key size)
      ISO7816.SW_WRONG_LENGTH
    );
    invariant(
      signKey.getPrivate().isInitialized(),
      ISO7816.SW_RECORD_NOT_FOUND
    );
    invariant(
      pw1.isValidated() || pinVerified[1],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );

    authBuffer[0] = (byte)0;
    authBuffer[1] = (byte)1;
    short data_len = Util.arrayFillNonAtomic(
      authBuffer, (short)2,
      (short)(253 - lc), // FIXME (make variable with key size)
      (byte)0xFF
    );
    authBuffer[data_len++] = (byte)0;
    data_len = Util.arrayCopyNonAtomic(
      buffer, ISO7816.OFFSET_CDATA,
      authBuffer, data_len,
      lc
    );

    cipher.init(signKey.getPrivate(), Cipher.MODE_ENCRYPT);
    outputChainingBuffer = keyReturnBuffer;
    outputChainingLength = data_len;
    outputChainingSent = (short)0;

    short le = cipher.doFinal(
      authBuffer, (short)0, data_len,
      outputChainingBuffer, (short)0
    );
    if (++signatureCounterLow == 0) {
      signatureCounterHigh++;
    }
    return Util.arrayCopyNonAtomic(
      outputChainingBuffer, (short)0,
      buffer, (short)0, le
    );
  }
}
