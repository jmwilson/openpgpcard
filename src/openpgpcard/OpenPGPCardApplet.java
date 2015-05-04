package openpgpcard;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacardx.framework.tlv.*;

public class OpenPGPCardApplet extends javacard.framework.Applet
  implements javacardx.apdu.ExtendedLength {

  private static final byte[] historicalBytes = {
    0x00,  // Category indicator
    0x73, (byte)0x80, 0x00, (byte)0x80,  // Capabilities
    0x03, (byte)0x90, 0x00  // Life cycle status and status indicator
  };

  private static final byte[] extendedCap = {
    0x78,
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

  private byte[] scratchBuffer;  // transient
  private boolean[] pw1ValidatedMode;  // transient

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

  private byte[] certificateBuffer1;
  private byte[] certificateBuffer2;
  private byte currentCertificate = (byte)0;

  private byte[] outputChainingBuffer;  // transient
  private short[] outputChain;  // transient
  private byte[] inputChain;  // transient

  private Cipher rsa;
  private RandomData randomGen;

  private KeyPair signKey;
  private byte[] signKeyFingerprint;
  private byte[] signKeyTimestamp;

  private KeyPair decryptKey;
  private byte[] decryptKeyFingerprint;
  private byte[] decryptKeyTimestamp;

  private KeyPair authKey;
  private byte[] authKeyFingerprint;
  private byte[] authKeyTimestamp;

  private KeyPair importKey;

  private byte[] ca1Fingerprint;
  private byte[] ca2Fingerprint;
  private byte[] ca3Fingerprint;

  private boolean terminated = false;

  private OpenPGPCardApplet() {
    pw1 = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    pw1.update(DEFAULT_PW1, (short)0, (byte)DEFAULT_PW1.length);
    pw1Length = (byte)DEFAULT_PW1.length;

    pw3 = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    pw3.update(DEFAULT_PW3, (short)0, (byte)DEFAULT_PW3.length);
    pw3Length = (byte)DEFAULT_PW3.length;

    rc = new OwnerPIN(OpenPGPCard.PIN_RETRIES, OpenPGPCard.MAX_PIN_LENGTH);
    rcLength = (byte)0;

    pw1ValidatedMode = JCSystem.makeTransientBooleanArray(
      (short)2, JCSystem.CLEAR_ON_DESELECT);
    scratchBuffer = JCSystem.makeTransientByteArray(
      (short)(KeyBuilder.LENGTH_RSA_2048 >> 3), JCSystem.CLEAR_ON_DESELECT);
    outputChain = JCSystem.makeTransientShortArray(
      (short)2, JCSystem.CLEAR_ON_DESELECT);
    inputChain = JCSystem.makeTransientByteArray(
      OpenPGPCard.INPUT_CHAIN_STATE_SIZE, JCSystem.CLEAR_ON_DESELECT);

    name = new byte[OpenPGPCard.NAME_SIZE];
    languagePrefs = new byte[OpenPGPCard.LANGUAGE_PREFS_SIZE];
    url = new byte[OpenPGPCard.URL_SIZE];
    loginData = new byte[OpenPGPCard.LOGIN_DATA_SIZE];

    // hax to get GPG to recognize the card as supporting PIN entry
    byte loginData_length = 0;
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

    signKey = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
    decryptKey = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
    authKey = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
    importKey = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);

    signKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    decryptKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    authKeyFingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];

    signKeyTimestamp = new byte[OpenPGPCard.TIMESTAMP_SIZE];
    decryptKeyTimestamp = new byte[OpenPGPCard.TIMESTAMP_SIZE];
    authKeyTimestamp = new byte[OpenPGPCard.TIMESTAMP_SIZE];

    ca1Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    ca2Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];
    ca3Fingerprint = new byte[OpenPGPCard.FINGERPRINT_SIZE];

    certificateBuffer1 = new byte[2 + OpenPGPCard.CERTIFICATE_SIZE];
    certificateBuffer2 = new byte[2 + OpenPGPCard.CERTIFICATE_SIZE];

    rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
    randomGen = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
  }

  public static void install(
    byte[] bArray, short bOffset, byte bLength) throws ISOException {
    new OpenPGPCardApplet().register(
      bArray, (short)(1 + bOffset), bArray[bOffset]
    );
  }

  public void process(APDU apdu) throws ISOException {
    short le = 0;

    try {
      le = _process(apdu);
    } catch (ISOException e) {
      outputChain[0] = outputChain[1] = (short)0;
      Util.arrayFillNonAtomic(
        inputChain, (short)0, OpenPGPCard.INPUT_CHAIN_STATE_SIZE, (byte)0);
      throw e;
    }

    if (le > (short)0) {
      apdu.setOutgoingLength(le);
      apdu.sendBytes((short)0, le);
      if (outputChain[0] < outputChain[1]) {
        short left = (short)(outputChain[1] - outputChain[0]);
        if (left > 0xFF) {
          left = 0xFF;
        }
        ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 | left));
      }
    }
  }

  private short _process(APDU apdu) throws ISOException {
    byte[] buffer = apdu.getBuffer();
    byte ins = buffer[ISO7816.OFFSET_INS];
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short p1p2 = Util.makeShort(p1, p2);
    short le = 0;

    if (terminated && ins != OpenPGPCard.CMD_ACTIVATE_FILE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (selectingApplet()) {
      return (short)0;
    }
    if (ins != OpenPGPCard.CMD_GET_RESPONSE) {
      outputChain[0]= outputChain[1] = (short)0;
    }
    if (inputChain[0] != 0) {
      if (inputChain[0] != ins || inputChain[1] != p1 ||
          inputChain[2] != p2) {
        ISOException.throwIt(ISO7816.SW_LAST_COMMAND_EXPECTED);
      }
    }
    if (apdu.isCommandChainingCLA()) {
      if (ins != OpenPGPCard.CMD_PUT_DATA && ins != OpenPGPCard.CMD_PUT_KEY) {
        ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
      }
      inputChain[0] = ins;
      inputChain[1] = p1;
      inputChain[2] = p2;
    } else {
      Util.arrayFillNonAtomic(
        inputChain, (short)0, OpenPGPCard.INPUT_CHAIN_STATE_SIZE, (byte)0);
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
        } else {
          ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        break;
      case OpenPGPCard.CMD_INTERNAL_AUTHENTICATE:
        le = internalAuthenticate(apdu);
        break;
      case OpenPGPCard.CMD_TERMINATE_DF:
        terminate(apdu);
        break;
      case OpenPGPCard.CMD_ACTIVATE_FILE:
        activate(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    return le;
  }

  private short getResponse(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short le = apdu.setOutgoing();
    short lr = (short)(outputChain[1] - outputChain[0]);

    invariant(p1 == 0 && p2 == 0, ISO7816.SW_INCORRECT_P1P2);
    if (lr > le) {
      lr = le;
    }
    outputChain[0] += Util.arrayCopyNonAtomic(
      outputChainingBuffer, outputChain[0],
      buffer, (short)0,
      lr
    );
    return lr;
  }

  private void verify(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = apdu.setIncomingAndReceive();
    short offset_cdata = apdu.getOffsetCdata();

    invariant(
      p1 == 0 && (p2 == (byte)0x81 || p2 == (byte)0x82 || p2 == (byte)0x83),
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(
      lc == apdu.getIncomingLength() &&
      OpenPGPCard.MIN_PIN_LENGTH <= lc && lc <= OpenPGPCard.MAX_PIN_LENGTH,
      ISO7816.SW_WRONG_LENGTH
    );

    if (p2 == (byte)0x81 || p2 == (byte)0x82) {
      if (!pw1.check(buffer, offset_cdata, (byte)lc)) {
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw1.getTriesRemaining()));
      }
      pw1ValidatedMode[(byte)(p2 - 0x81)] = true;
    } else if (p2 == (byte)0x83) {
      if (!pw3.check(buffer, offset_cdata, (byte)lc)) {
        ISOException.throwIt(
          (short)(OpenPGPCard.SW_PIN_FAILED_00 | pw3.getTriesRemaining()));
      }
    }
  }

  private void changeReferenceData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = apdu.setIncomingAndReceive();
    short offset_cdata = apdu.getOffsetCdata();
    byte new_length;

    invariant(
      p1 == 0 && (p2 == (byte)0x81 || p2 == (byte)0x83),
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(lc == apdu.getIncomingLength(), ISO7816.SW_WRONG_LENGTH);

    if (p2 == (byte)0x81) {
      if (!pw1.check(buffer, offset_cdata, (byte)pw1Length)) {
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
        buffer, (short)(offset_cdata + pw1Length), new_length);
      pw1Length = new_length;
      JCSystem.commitTransaction();
      pw1ValidatedMode[0] = pw1ValidatedMode[1] = false;
    } else if (p2 == (byte)0x83) {
      if (!pw3.check(buffer, offset_cdata, (byte)pw3Length)) {
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
        buffer, (short)(offset_cdata + pw3Length), new_length);
      pw3Length = new_length;
      JCSystem.commitTransaction();
    }
  }

  private void resetRetryCounter(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = apdu.setIncomingAndReceive();
    short offset_cdata = apdu.getOffsetCdata();
    byte new_length;

    invariant(p2 == (byte)0x81, ISO7816.SW_INCORRECT_P1P2);
    invariant(apdu.getIncomingLength() == lc, ISO7816.SW_WRONG_LENGTH);
    if (p1 == 0) {
      new_length = (byte)(lc - rcLength);
      if (!rc.check(buffer, offset_cdata, rcLength)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      invariant(
        OpenPGPCard.MIN_PIN_LENGTH <= new_length &&
        new_length <= OpenPGPCard.MAX_PIN_LENGTH,
        ISO7816.SW_WRONG_LENGTH
      );

      pw1ValidatedMode[0] = pw1ValidatedMode[1] = false;
      JCSystem.beginTransaction();
      pw1.update(buffer, (short)(offset_cdata + rcLength), new_length);
      pw1Length = new_length;
      JCSystem.commitTransaction();
    } else if (p1 == 2) {
      invariant(pw3.isValidated(), ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      invariant(
        OpenPGPCard.MIN_PIN_LENGTH <= lc && lc <= OpenPGPCard.MAX_PIN_LENGTH,
        ISO7816.SW_WRONG_LENGTH
      );

      pw1ValidatedMode[0] = pw1ValidatedMode[1] = false;
      JCSystem.beginTransaction();
      pw1.update(buffer, offset_cdata, (byte)lc);
      pw1Length = (byte)lc;
      JCSystem.commitTransaction();
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  private short getData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short tag = Util.makeShort(
      buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
    short data_len = 0;
    short tmp_length;
    short le = apdu.setOutgoing();

    switch (tag) {
      case OpenPGPCard.DO_PRIVATE_1:
        return Util.arrayCopyNonAtomic(
          privateDO1, (short)1, buffer, (short)0, (short)(privateDO1[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_2:
        return Util.arrayCopyNonAtomic(
          privateDO2, (short)1, buffer, (short)0, (short)(privateDO2[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_3:
        return Util.arrayCopyNonAtomic(
          privateDO3, (short)1, buffer, (short)0, (short)(privateDO3[0] & 0xFF)
        );
      case OpenPGPCard.DO_PRIVATE_4:
        return Util.arrayCopyNonAtomic(
          privateDO4, (short)1, buffer, (short)0, (short)(privateDO4[0] & 0xFF)
        );
      case OpenPGPCard.DO_AID:
        return JCSystem.getAID().getBytes(buffer, (short)0);
      case OpenPGPCard.DO_LOGIN_DATA:
        return Util.arrayCopyNonAtomic(
          loginData, (short)1, buffer, (short)0, (short)(loginData[0] & 0xFF));
      case OpenPGPCard.DO_URL:
        return Util.arrayCopyNonAtomic(
          url, (short)1, buffer, (short)0, (short)(url[0] & 0xFF));
      case OpenPGPCard.DO_HISTORICAL_BYTES:
        return Util.arrayCopyNonAtomic(
          historicalBytes, (short)0, buffer, (short)0,
          (short)historicalBytes.length
        );
      case OpenPGPCard.DO_CARDHOLDER_DATA:  // TLV encoded
        // Header size = 2 bytes
        buffer[data_len++] = (byte)OpenPGPCard.DO_CARDHOLDER_DATA;
        buffer[data_len++] = (byte)0;  // placeholder for length

        buffer[data_len++] = (byte)OpenPGPCard.DO_NAME;
        data_len = Util.arrayCopyNonAtomic(
          name, (short)0, buffer, data_len, (short)(1 + name[0]));
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.DO_LANGUAGE_PREFS);
        data_len = Util.arrayCopyNonAtomic(
          languagePrefs, (short)0,
          buffer, data_len,
          (short)(1 + languagePrefs[0])
        );
        data_len = Util.setShort(buffer, data_len, OpenPGPCard.DO_SEX);
        buffer[data_len++] = (byte)1;
        buffer[data_len++] = sex;
        buffer[1] = (byte)(data_len - 2);
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
          historicalBytes, (short)0, buffer, data_len,
          (short)historicalBytes.length
        );

        buffer[data_len++] = (byte)OpenPGPCard.DO_DISCRETIONARY_DOS;
        buffer[data_len++] = (byte)0x81;
        tmp_length = data_len++;
        buffer[data_len++] = (byte)OpenPGPCard.DO_EXTENDED_CAP;
        buffer[data_len++] = (byte)extendedCap.length;
        data_len = Util.arrayCopyNonAtomic(
          extendedCap, (short)0, buffer, data_len, (short)extendedCap.length);

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_SIGN;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(
          buffer, data_len, signKey.getPrivate().getSize());
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.RSA_EXPONENT_BITS);
        buffer[data_len++] = OpenPGPCard.RSA_FORMAT_CRT_MODULUS;

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_DECRYPT;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(
          buffer, data_len, decryptKey.getPrivate().getSize());
        data_len = Util.setShort(
          buffer, data_len, OpenPGPCard.RSA_EXPONENT_BITS);
        buffer[data_len++] = OpenPGPCard.RSA_FORMAT_CRT_MODULUS;

        buffer[data_len++] = (byte)OpenPGPCard.DO_ALGORITHM_ATTR_AUTH;
        buffer[data_len++] = (byte)6;
        buffer[data_len++] = OpenPGPCard.ALGORITHM_ID_RSA;
        data_len = Util.setShort(
          buffer, data_len, authKey.getPrivate().getSize());
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
        data_len = copyKeyFingerprints(buffer, data_len);

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
          signKeyTimestamp, (short)0,
          buffer, data_len,
          OpenPGPCard.TIMESTAMP_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          decryptKeyTimestamp, (short)0,
          buffer, data_len,
          OpenPGPCard.TIMESTAMP_SIZE
        );
        data_len = Util.arrayCopyNonAtomic(
          authKeyTimestamp, (short)0,
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
        return copyKeyFingerprints(buffer, data_len);
      case OpenPGPCard.DO_SECURITY_TEMPLATE:  // TLV encoded
        buffer[data_len++] = (byte)OpenPGPCard.DO_SECURITY_TEMPLATE;
        buffer[data_len++] = (byte)5;
        buffer[data_len++] = (byte)OpenPGPCard.DO_SIGNATURE_COUNTER;
        buffer[data_len++] = (byte)3;
        buffer[data_len++] = signatureCounterHigh;
        return Util.setShort(buffer, data_len, signatureCounterLow);
      case OpenPGPCard.DO_CERTIFICATE:  // TLV encoded
        data_len = Util.setShort(buffer, data_len, OpenPGPCard.DO_CERTIFICATE);
        byte[] cert = currentCertificate == (byte)0
          ? certificateBuffer1
          : certificateBuffer2;
        short cert_length = Util.getShort(cert, (short)0);
        if (cert_length < (short)0x80) {
          buffer[data_len++] = (byte)cert_length;
        } else if (cert_length < (short)0x100) {
          buffer[data_len++] = (byte)0x81;
          buffer[data_len++] = (byte)cert_length;
        } else {
          buffer[data_len++] = (byte)0x82;
          data_len = Util.setShort(buffer, data_len, cert_length);
        }

        if ((short)(data_len + cert_length) < le) {
          return Util.arrayCopyNonAtomic(
            cert, (short)2, buffer, data_len, cert_length);
        } else {
          // First two bytes are length, so adjust length and offset.
          outputChainingBuffer = cert;
          outputChain[1] = (short)(2 + cert_length);
          outputChain[0] = (short)(2 + le - data_len);
          data_len += Util.arrayCopyNonAtomic(
            cert, (short)2, buffer, data_len, (short)(le - data_len));
          return data_len;
        }
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    return (short)0;
  }

  private short copyKeyFingerprints(byte[] buffer, short offset) {
    if (signKey.getPublic().isInitialized()) {
      offset = Util.arrayCopyNonAtomic(
        signKeyFingerprint, (short)0,
        buffer, offset,
        OpenPGPCard.FINGERPRINT_SIZE
      );
    } else {
      offset = Util.arrayFillNonAtomic(
        buffer, offset, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    }
    if (decryptKey.getPublic().isInitialized()) {
      offset = Util.arrayCopyNonAtomic(
        decryptKeyFingerprint, (short)0,
        buffer, offset,
        OpenPGPCard.FINGERPRINT_SIZE
      );
    } else {
      offset = Util.arrayFillNonAtomic(
        buffer, offset, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    }
    if (authKey.getPublic().isInitialized()) {
      offset = Util.arrayCopyNonAtomic(
        authKeyFingerprint, (short)0,
        buffer, offset,
        OpenPGPCard.FINGERPRINT_SIZE
      );
    } else {
      offset = Util.arrayFillNonAtomic(
        buffer, offset, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    }
    return offset;
  }

  private void putData(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte cla = buffer[ISO7816.OFFSET_CLA];
    short tag = Util.makeShort(
      buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
    short lc = apdu.setIncomingAndReceive();
    short offset_cdata = apdu.getOffsetCdata();

    invariant(apdu.getIncomingLength() == lc, ISO7816.SW_WRONG_LENGTH);
    if (apdu.isCommandChainingCLA() && tag != OpenPGPCard.DO_CERTIFICATE) {
      ISOException.throwIt(ISO7816.SW_COMMAND_CHAINING_NOT_SUPPORTED);
    }

    if (tag == OpenPGPCard.DO_PRIVATE_1 || tag == OpenPGPCard.DO_PRIVATE_3) {
      if (!(pw1.isValidated() && pw1ValidatedMode[1])) {
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      }
    } else if (!pw3.isValidated()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    switch (tag) {
      case OpenPGPCard.DO_PRIVATE_1:
        invariant(lc < OpenPGPCard.PRIVATE_DO_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          privateDO1, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_2:
        invariant(lc < OpenPGPCard.PRIVATE_DO_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_3:
        invariant(lc < OpenPGPCard.PRIVATE_DO_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_PRIVATE_4:
        invariant(lc < OpenPGPCard.PRIVATE_DO_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          privateDO2, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_NAME:
        invariant(lc < OpenPGPCard.NAME_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          name, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_LOGIN_DATA:
        invariant(lc < OpenPGPCard.LOGIN_DATA_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          name, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_LANGUAGE_PREFS:
        invariant(
          lc < OpenPGPCard.LANGUAGE_PREFS_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          languagePrefs, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_SEX:
        invariant(lc == 1, ISO7816.SW_WRONG_LENGTH);
        invariant(
          buffer[offset_cdata] == OpenPGPCard.ISO5218_MALE ||
          buffer[offset_cdata] == OpenPGPCard.ISO5218_FEMALE ||
          buffer[offset_cdata] == OpenPGPCard.ISO5218_NOT_APPLICABLE,
          ISO7816.SW_WRONG_DATA
        );
        sex = buffer[offset_cdata];
        break;
      case OpenPGPCard.DO_URL:
        invariant(lc < OpenPGPCard.URL_SIZE, ISO7816.SW_WRONG_LENGTH);
        Util.arrayCopy(
          buffer, (short)(offset_cdata - 1),
          url, (short)0,
          (short)(1 + lc)
        );
        break;
      case OpenPGPCard.DO_CERTIFICATE:
        byte[] cert = currentCertificate == (byte)0
          ? certificateBuffer2
          : certificateBuffer1;
        short offset = Util.getShort(cert, (short)0);
        invariant(
          (short)(offset + lc) <= OpenPGPCard.CERTIFICATE_SIZE,
          ISO7816.SW_WRONG_LENGTH
        );
        JCSystem.beginTransaction();
        offset = Util.arrayCopy(
          buffer, offset_cdata, cert, (short)(2 + offset), lc);
        Util.setShort(cert, (short)0, (short)(offset - 2));
        if (!apdu.isCommandChainingCLA()) {
          currentCertificate ^= 1;
        }
        JCSystem.commitTransaction();
        break;
      case OpenPGPCard.DO_PW_STATUS:
        invariant(lc == (short)1, (short)(ISO7816.SW_CORRECT_LENGTH_00 | 1));
        if (buffer[offset_cdata] == 0) {
          forceSignaturePIN = true;
        } else if (buffer[offset_cdata] == 1) {
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
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
          buffer, offset_cdata,
          signKeyTimestamp, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_GENERATION_TIME_DECRYPT:
        invariant(
          lc == OpenPGPCard.TIMESTAMP_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.TIMESTAMP_SIZE)
        );
        Util.arrayCopy(
          buffer, offset_cdata,
          decryptKeyTimestamp, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_GENERATION_TIME_AUTH:
        invariant(
          lc == OpenPGPCard.TIMESTAMP_SIZE,
          (short)(ISO7816.SW_CORRECT_LENGTH_00 | OpenPGPCard.TIMESTAMP_SIZE)
        );
        Util.arrayCopy(
          buffer, offset_cdata,
          authKeyTimestamp, (short)0,
          lc
        );
        break;
      case OpenPGPCard.DO_RESET_CODE:
        invariant(
          lc == (short)0 ||
          (OpenPGPCard.MIN_RC_LENGTH <= lc && lc <= OpenPGPCard.MAX_PIN_LENGTH),
          ISO7816.SW_WRONG_LENGTH
        );
        rc.update(buffer, offset_cdata, (byte)lc);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  private short generateKey(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = apdu.setIncomingAndReceive();

    invariant(
      (p1 == (byte)0x80 || p1 == (byte)0x81) && p2 == (byte)0,
      ISO7816.SW_INCORRECT_P1P2
    );
    invariant(lc == apdu.getIncomingLength(), ISO7816.SW_WRONG_LENGTH);
    invariant(lc == (short)2, (short)(ISO7816.SW_CORRECT_LENGTH_00 | 2));

    short crt = Util.getShort(buffer, apdu.getOffsetCdata());
    KeyPair key = null;
    if (crt == OpenPGPCard.CRT_SIGN_KEY) {
      key = signKey;
    } else if (crt == OpenPGPCard.CRT_DECRYPT_KEY) {
      key = decryptKey;
    } else if (crt == OpenPGPCard.CRT_AUTH_KEY) {
      key = authKey;
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

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

    invariant(key.getPublic().isInitialized(), ISO7816.SW_FILE_NOT_FOUND);

    // Send the exponent and modulus header in the first response, since
    // they are small. Return the modulus in subsequent GET_RESPONSE operations.

    // Header, length = 5
    short data_len = (short)0;
    data_len = Util.setShort(buffer, data_len, (short)0x7F49);
    buffer[data_len++] = (byte)0x82;  // 2 bytes of length follow
    data_len += 2;  // placeholder for length at offset 3

    // Exponent block, length = 2 (1 header + 1 length) + exp_length
    buffer[data_len++] = (byte)0x82;
    byte exp_length = (byte)((RSAPublicKey)key.getPublic()).getExponent(
      buffer, (short)(1 + data_len));
    buffer[data_len] = exp_length;
    data_len += 1 + exp_length;

    // Key block, length = 4 (1 header + 3 length) + key_size
    buffer[data_len++] = (byte)0x81;
    buffer[data_len++] = (byte)0x82;  // 2 bytes of length follow
    short key_size =
      ((RSAPublicKey)key.getPublic()).getModulus(scratchBuffer, (short)0);
    data_len = Util.setShort(buffer, data_len, key_size);
    outputChainingBuffer = scratchBuffer;
    outputChain[1] = key_size;
    outputChain[0] = (short)0;

    // Go back and set the header length at offset 3
    Util.setShort(buffer, (short)3, (short)(2 + exp_length + 4 + key_size));
    apdu.setOutgoing();
    return data_len;
  }

  private short computeSignature(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = apdu.setIncomingAndReceive();

    invariant(lc == apdu.getIncomingLength(), ISO7816.SW_WRONG_LENGTH);
    invariant(
      signKey.getPrivate().isInitialized(),
      ISO7816.SW_RECORD_NOT_FOUND
    );
    invariant(
      pw1.isValidated() && pw1ValidatedMode[0],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );
    if (forceSignaturePIN) {
      pw1ValidatedMode[0] = false;
    }

    Util.arrayCopyNonAtomic(
      buffer, apdu.getOffsetCdata(), scratchBuffer, (short)0, lc);
    if (++signatureCounterLow == 0) {
      signatureCounterHigh++;
    }
    apdu.setOutgoing();
    rsa.init(signKey.getPrivate(), Cipher.MODE_ENCRYPT);
    return rsa.doFinal(scratchBuffer, (short)0, lc, buffer, (short)0);
  }

  private short decipher(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short lc = apdu.setIncomingAndReceive();

    invariant(lc == apdu.getIncomingLength(), ISO7816.SW_WRONG_LENGTH);
    invariant(
      decryptKey.getPrivate().isInitialized(),
      ISO7816.SW_RECORD_NOT_FOUND
    );
    invariant(
      pw1.isValidated() && pw1ValidatedMode[1],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );

    Util.arrayCopyNonAtomic(
      buffer, apdu.getOffsetCdata(), scratchBuffer, (short)0, lc);
    apdu.setOutgoing();
    rsa.init(decryptKey.getPrivate(), Cipher.MODE_DECRYPT);
    return rsa.doFinal(scratchBuffer, (short)0, lc, buffer, (short)0);
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
    short le = apdu.setOutgoing();

    invariant(p1 == 0 && p2 == 0, ISO7816.SW_INCORRECT_P1P2);
    try {
      randomGen.generateData(buffer, (short)0, le);
    } catch (CryptoException e) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return le;
  }

  private short internalAuthenticate(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];
    short lc = apdu.setIncomingAndReceive();

    invariant(p1 == 0 && p2 == 0, ISO7816.SW_INCORRECT_P1P2);
    invariant(
      lc == apdu.getIncomingLength() && lc <= 102, ISO7816.SW_WRONG_LENGTH);
    invariant(
      authKey.getPrivate().isInitialized(), ISO7816.SW_RECORD_NOT_FOUND);
    invariant(
      pw1.isValidated() && pw1ValidatedMode[1],
      ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED
    );

    Util.arrayCopyNonAtomic(
      buffer, apdu.getOffsetCdata(), scratchBuffer, (short)0, lc);
    apdu.setOutgoing();
    rsa.init(authKey.getPrivate(), Cipher.MODE_ENCRYPT);
    return rsa.doFinal(scratchBuffer, (short)0, lc, buffer, (short)0);
  }

  private void terminate(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];

    invariant(p1 == 0 && p2 == 0, ISO7816.SW_INCORRECT_P1P2);
    invariant(
      pw1.getTriesRemaining() == 0 && pw3.getTriesRemaining() == 0,
      ISO7816.SW_CONDITIONS_NOT_SATISFIED
    );

    terminated = true;
  }

  private void activate(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    byte p1 = buffer[ISO7816.OFFSET_P1];
    byte p2 = buffer[ISO7816.OFFSET_P2];

    invariant(p1 == 0 && p2 == 0, ISO7816.SW_INCORRECT_P1P2);
    if (!terminated) {
      return;
    }

    pw1.update(DEFAULT_PW1, (short)0, (byte)DEFAULT_PW1.length);
    pw1Length = (byte)DEFAULT_PW1.length;
    pw3.update(DEFAULT_PW3, (short)0, (byte)DEFAULT_PW3.length);
    pw3Length = (byte)DEFAULT_PW3.length;
    rcLength = (byte)0;

    signKey.getPrivate().clearKey();
    signKey.getPublic().clearKey();
    decryptKey.getPrivate().clearKey();
    decryptKey.getPublic().clearKey();
    authKey.getPrivate().clearKey();
    authKey.getPublic().clearKey();

    Util.arrayFillNonAtomic(
      name, (short)0, OpenPGPCard.NAME_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      languagePrefs, (short)0, OpenPGPCard.LANGUAGE_PREFS_SIZE, (byte)0);
    Util.arrayFillNonAtomic(url, (short)0, OpenPGPCard.URL_SIZE, (byte)0);
    sex = OpenPGPCard.ISO5218_NOT_APPLICABLE;
    Util.arrayFillNonAtomic(
      loginData, (short)0, OpenPGPCard.LOGIN_DATA_SIZE, (byte)0);

    Util.arrayFillNonAtomic(
      privateDO1, (short)0, OpenPGPCard.PRIVATE_DO_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      privateDO2, (short)0, OpenPGPCard.PRIVATE_DO_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      privateDO3, (short)0, OpenPGPCard.PRIVATE_DO_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      privateDO4, (short)0, OpenPGPCard.PRIVATE_DO_SIZE, (byte)0);

    Util.arrayFillNonAtomic(
      signKeyFingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      decryptKeyFingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      authKeyFingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);

    Util.arrayFillNonAtomic(
      signKeyTimestamp, (short)0, OpenPGPCard.TIMESTAMP_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      decryptKeyTimestamp, (short)0, OpenPGPCard.TIMESTAMP_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      authKeyTimestamp, (short)0, OpenPGPCard.TIMESTAMP_SIZE, (byte)0);

    Util.arrayFillNonAtomic(
      ca1Fingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      ca2Fingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);
    Util.arrayFillNonAtomic(
      ca3Fingerprint, (short)0, OpenPGPCard.FINGERPRINT_SIZE, (byte)0);

    forceSignaturePIN = true;
    signatureCounterHigh = (byte)0;
    signatureCounterLow = (short)0;

    Util.arrayFillNonAtomic(
      certificateBuffer1,
      (short)0, (short)(2 + OpenPGPCard.CERTIFICATE_SIZE), (byte)0);
    Util.arrayFillNonAtomic(
      certificateBuffer2,
      (short)0, (short)(2 + OpenPGPCard.CERTIFICATE_SIZE), (byte)0);
    currentCertificate = (byte)0;

    terminated = false;
  }
}
