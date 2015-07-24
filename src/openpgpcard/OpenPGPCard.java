/*
 * Copyright (C) 2015 James M Wilson <jmw@fastmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package openpgpcard;

public interface OpenPGPCard {
	public static short SW_PIN_FAILED_00 = 0x63C0;

	public static byte CMD_VERIFY = 0x20;
	public static byte CMD_GET_RESPONSE = (byte)0xC0;
	public static byte CMD_CHANGE_REFERENCE_DATA = 0x24;
	public static byte CMD_RESET_RETRY_COUNTER = 0x2C;
	public static byte CMD_GET_CHALLENGE = (byte)0x84;
	public static byte CMD_SELECT_DATA = (byte)0xA5;
	public static byte CMD_GET_DATA = (byte)0xCA;
	public static byte CMD_GET_NEXT_DATA = (byte)0xCC;
	public static byte CMD_PUT_DATA = (byte)0xDA;
	public static byte CMD_PUT_KEY = (byte)0xDB;
	public static byte CMD_GENERATE_ASYMMETRIC_KEY_PAIR = 0x47;
	public static byte CMD_PERFORM_SECURITY_OPERATION = 0x2A;
	public static byte CMD_INTERNAL_AUTHENTICATE = (byte)0x88;
	public static byte CMD_TERMINATE_DF = (byte)0xE6;
	public static byte CMD_ACTIVATE_FILE = 0x44;

	public static short PSO_SIGNATURE = (short)0x9E9A;
	public static short PSO_DECIPHER = (short)0x8086;

	public static short PRIVATE_DO_SIZE = 255;

	public static byte PIN_RETRIES = 3;
	public static byte MIN_PIN_LENGTH = 6;
	public static byte MAX_PIN_LENGTH = 32;
	public static byte MIN_RC_LENGTH = 8;

	public static short NAME_SIZE = 40;
	public static short LANGUAGE_PREFS_SIZE = 9;
	public static short URL_SIZE = 255;
	public static short LOGIN_DATA_SIZE = 255;

	public static byte ISO5218_MALE = 0x31;
	public static byte ISO5218_FEMALE = 0x32;
	public static byte ISO5218_NOT_APPLICABLE = 0x39;

	public static short CERTIFICATE_SIZE = 4096;

	public static short DO_PRIVATE_1 = 0x0101;
	public static short DO_PRIVATE_2 = 0x0102;
	public static short DO_PRIVATE_3 = 0x0103;
	public static short DO_PRIVATE_4 = 0x0104;
	public static short DO_AID = 0x004F;
	public static short DO_LOGIN_DATA = 0x005E;
	public static short DO_URL = 0x5F50;
	public static short DO_HISTORICAL_BYTES = 0x5F52;
	public static short DO_EXTENDED_LENGTH_INFO = 0x7F66;
	public static short DO_GENERAL_FEATURE_MANAGEMENT = 0x7F74;
	public static short DO_CARDHOLDER_DATA = 0x0065;
	public static short DO_NAME = 0x005B;
	public static short DO_LANGUAGE_PREFS = 0x5F2D;
	public static short DO_SEX = 0x5F35;
	public static short DO_APPLICATION_DATA = 0x006E;
	public static short DO_DISCRETIONARY_DOS = 0x0073;
	public static short DO_EXTENDED_CAP = 0x00C0;
	public static short DO_ALGORITHM_ATTR_SIGN = 0x00C1;
	public static short DO_ALGORITHM_ATTR_DECRYPT = 0x00C2;
	public static short DO_ALGORITHM_ATTR_AUTH = 0x00C3;
	public static short DO_PW_STATUS = 0x00C4;
	public static short DO_FINGERPRINTS = 0x00C5;
	public static short DO_FINGERPRINT_SIGN = 0x00C7;
	public static short DO_FINGERPRINT_DECRYPT = 0x00C8;
	public static short DO_FINGERPRINT_AUTH = 0x00C9;
	public static short DO_CA_FINGERPRINTS = 0x00C6;
	public static short DO_FINGERPRINT_CA_1 = 0x00CA;
	public static short DO_FINGERPRINT_CA_2 = 0x00CB;
	public static short DO_FINGERPRINT_CA_3 = 0x00CC;
	public static short DO_GENERATION_TIMES = 0x00CD;
	public static short DO_GENERATION_TIME_SIGN = 0x00CE;
	public static short DO_GENERATION_TIME_DECRYPT = 0x00CF;
	public static short DO_GENERATION_TIME_AUTH = 0x00D0;
	public static short DO_SM_KEY_ENC = 0x00D1;
	public static short DO_SM_KEY_MAC = 0x00D2;
	public static short DO_SM_KEYS = 0x00F4;
	public static short DO_RESET_CODE = 0x00D3;
	public static short DO_SECURITY_TEMPLATE = 0x007A;
	public static short DO_SIGNATURE_COUNTER = 0x0093;
	public static short DO_CERTIFICATE = 0x7F21;
	public static short DO_PRIVATE_KEY_DATA = 0x5F48;
	public static short DO_PRIVATE_KEY_TEMPLATE = 0x7F48;
	public static short DO_PUBLIC_KEY = 0x7F49;

	public static byte ALGORITHM_ID_RSA = 1;
	public static byte ALGORITHM_ID_ECDSA = 19;
	public static byte ALGORITHM_ID_ECDH = 18;
	public static byte RSA_EXPONENT_BITS = 32;
	public static byte RSA_FORMAT_CRT_MODULUS = 3;
	public static byte FINGERPRINT_SIZE = 20;
	public static byte TIMESTAMP_SIZE = 4;

	public static short CRT_SIGN_KEY = (short)0xB600;
	public static short CRT_DECRYPT_KEY = (short)0xB800;
	public static short CRT_AUTH_KEY = (short)0xA400;
}
