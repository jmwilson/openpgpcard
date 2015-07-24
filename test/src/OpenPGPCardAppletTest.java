/*
* Copyright (C) 2013 Yubico AB
* Copyright (C) 2015 James M Wilson <jmw@fastmail.com>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

import java.util.Arrays;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import openpgpcard.OpenPGPCard;
import openpgpcard.OpenPGPCardApplet;

import org.junit.Before;
import org.junit.Test;

import com.licel.jcardsim.base.Simulator;

public class OpenPGPCardAppletTest {
	Simulator simulator;
	static final byte[] pgpAid = new byte[] {(byte) 0xd2, 0x76, 0x00, 0x01, 0x24,
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
	static final AID aid = new AID(pgpAid, (short)0, (byte)pgpAid.length);
	static final byte[] success = {(byte) 0x90, 0x00};

	@Before
	public void setup() {
		byte[] params = new byte[pgpAid.length + 1];
		params[0] = (byte) pgpAid.length;
		System.arraycopy(pgpAid, 0, params, 1, pgpAid.length);

		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, OpenPGPCardApplet.class, params, (short)0, (byte) params.length);
		simulator.selectApplet(aid);
	}

	@Test
	public void testActivate() {
		byte[] resp = simulator.transmitCommand(new byte[] {
			0x00, 0x44, 0x00, 0x00, 0x00,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x44, 0x01, 0x00, 0x00,
		});
		assertEquals(ISO7816.SW_INCORRECT_P1P2, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x44, 0x00, 0x01, 0x00,
		});
		assertEquals(ISO7816.SW_INCORRECT_P1P2, sw(resp));
	}

	@Test
	public void testVerify() {
		byte[] resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x81, 8,
			'1', '2', '3', '4', '5', '6', (byte)0xff, (byte)0xff,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x83, 8,
			'1', '2', '3', '4', '5', '6', '7', '8',
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x01, (byte)0x81, 8,
			'1', '2', '3', '4', '5', '6', '7', '8',
		});
		assertEquals(ISO7816.SW_INCORRECT_P1P2, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x00, 8,
			'1', '2', '3', '4', '5', '6', '7', '8',
		});
		assertEquals(ISO7816.SW_INCORRECT_P1P2, sw(resp));
	}

	@Test
	public void testGenerate() {
		assertEquals(true, doVerify("12345678", (byte) 0x83));
		byte[] command = {0x00, 0x47, (byte) 0x80, 0x00, 0x01, (byte) 0xb6};
		simulator.transmitCommand(command);
	}

	@Test
	public void testTerminate() {
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte) 0xe6, 0, 0});
		assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, sw(resp));

		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertArrayEquals(new byte[] {0, 3, 2}, getPinRetries());
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertArrayEquals(new byte[] {0, 3, 1}, getPinRetries());
		assertEquals(false, doVerify("87654321", (byte) 0x83));
		assertArrayEquals(new byte[] {0, 3, 0}, getPinRetries());
		assertEquals(false, doVerify("123456", (byte) 0x81));

		resp = simulator.transmitCommand(new byte[] {0, (byte) 0xe6, 0, 0});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		// All commands other than ACTIVATE should fail.
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x4f});
		assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, 0x44, 0, 0});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x81, 8,
			'1', '2', '3', '4', '5', '6', (byte)0xff, (byte)0xff,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
	}

	@Test
	public void testUnblock() {
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("123456", (byte) 0x81));

		assertEquals(true, doVerify("12345678", (byte) 0x83));
		byte[] res = simulator.transmitCommand(new byte[] {0, 0x2c, 0x02, (byte) 0x81, 0x06,
				'6', '5', '4', '3', '2', '1'});
		assertArrayEquals(success,  res);

		assertEquals(true, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
	}

	@Test
	public void testRcUnblock() {
		byte[] newRc = {0, (byte) 0xda, 0, (byte) 0xd3, 8, '8', '7', '6', '5', '4', '3', '2', '1'};
		assertEquals(true, doVerify("12345678", (byte) 0x83));
		assertEquals(ISO7816.SW_NO_ERROR, sw(simulator.transmitCommand(newRc)));
		simulator.reset();
		simulator.selectApplet(aid);

		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {2, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {1, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {0, 3, 3}, getPinRetries());
		assertEquals(false, doVerify("123456", (byte) 0x81));

		byte[] res = simulator.transmitCommand(new byte[] {
			0, 0x2c, 0, (byte) 0x81, 14,
			'8', '7', '6', '5', '4', '3', '2', '1',
			'6', '5', '4', '3', '2', '1'
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(res));
		assertEquals(true, doVerify("654321", (byte) 0x81));
		assertArrayEquals(new byte[] {3, 3, 3}, getPinRetries());
	}

	@Test
	public void testSetCertificate() {
		byte[] data = {0, (byte) 0xda, 0x7f, 0x21, 8, 1, 2, 3, 4, 5, 6, 7, 8};
		byte[] resp = simulator.transmitCommand(data);
		assertArrayEquals(new byte[] {0x69, (byte) 0x82}, resp);
		assertEquals(true, doVerify("12345678", (byte) 0x83));
		resp = simulator.transmitCommand(data);
		assertArrayEquals(success, resp);

		simulator.reset();
		simulator.selectApplet(aid);
		byte[] expect = {0x7f, 0x21, 8, 1, 2, 3, 4, 5, 6, 7, 8, (byte) 0x90, 0};
		resp = simulator.transmitCommand(new byte[] {0, (byte) 0xca, 0x7f, 0x21});
		assertArrayEquals(expect, resp);
	}

	@Test
	public void testGetData() {
		// 4f: AID, should match test environment AID
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x4f});
		assertArrayEquals(pgpAid, Arrays.copyOfRange(resp, 0, resp.length-2));
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		// 5e: login data
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x5e});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		// 5f50: URL
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x5f, 0x50});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		// 5f52: historical bytes
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x5f, 0x52});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		assertArrayEquals(
			new byte[] {
				0x5f, 0x52, 0x08, 0x00, 0x73, (byte)0x80, 0x00, (byte)0x80, 0x05, (byte)0x90, 0x00
			},
			Arrays.copyOfRange(resp, 0, resp.length - 2)
		);

		// 7f66: extended length information
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x7f, 0x66});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		assertArrayEquals(
			new byte[] {
				0x7f, 0x66, 0x08,
				0x02, 0x02, 0x01, 0x00,
				0x02, 0x02, 0x01, 0x00,
			},
			Arrays.copyOfRange(resp, 0, resp.length - 2)
		);

		// 7f74: general feature management
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x7f, 0x74});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		assertArrayEquals(
			new byte[] {0x7f, 0x74, 0x03, (byte)0x81, 0x01, 0x00},
			Arrays.copyOfRange(resp, 0, resp.length - 2)
		);

		// 7a: security support template
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x7a});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		assertArrayEquals(
			new byte[] {0x7a, 0x05, (byte)0x93, 0x03, 0x00, 0x00, 0x00},
			Arrays.copyOfRange(resp, 0, resp.length - 2)
		);

		// c4: PW status bytes
		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, (byte)0xc4});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		assertEquals(7, resp.length - 2);
	}

	@Test
	public void testSelectData() {
		byte[] resp = simulator.transmitCommand(new byte[] {
			0x00, (byte)0xA5, 0x00, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21, 0x00,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, (byte)0xA5, 0x01, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21, 0x00,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, (byte)0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21, 0x00,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {
			0x00, (byte)0xA5, 0x03, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21, 0x00,
		});
		assertEquals(ISO7816.SW_INCORRECT_P1P2, sw(resp));
	}

	// Assumes DOs are transmitted in the same order as listed in §4.4.1,
	// even though the spec permits any ordering inside a constructed DO.
	@Test
	public void testReadCardholderData() {
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x65});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		assertEquals(0x65, resp[0]);
		assertEquals(resp[1], resp.length - 4);

		int i = 2;
		assertEquals(0x5b, resp[i++]);
		assertEquals(0, resp[i] & 0x80);
		i += 1 + resp[i];

		assertEquals(0x5F2D, Util.getShort(resp, (short)i));
		i += 2;
		assertEquals(0, resp[i] & 0x80);
		i += 1 + resp[i];

		assertEquals(0x5F35, Util.getShort(resp, (short)i));
		i += 2;
		assertEquals(1, resp[i++]);
		assertEquals(0x39, resp[i++]);

		assertEquals(resp.length - 2, i);
	}

	// Assumes DOs are transmitted in the same order as listed in §4.4.1,
	// even though the spec permits any ordering inside a constructed DO.
	@Test
	public void testReadApplicationData() {
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x00, 0x6e});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		assertEquals(0x6e, resp[0]);
		assertEquals(0x82, resp[1] & 0xff);
		assertEquals(Util.getShort(resp, (short)2), resp.length - 6);

		int i = 4;
		assertEquals(0x4f, resp[i++]);
		assertEquals(0, resp[i] & 0x80);
		assertArrayEquals(pgpAid, Arrays.copyOfRange(resp, i + 1, i + 1 + pgpAid.length));
		i += 1 + resp[i];

		assertEquals(0x5F52, Util.getShort(resp, (short)i));
		i += 2;
		assertEquals(0, resp[i] & 0x80);
		i += 1 + resp[i];

		assertEquals(0x7F66, Util.getShort(resp, (short)i));
		i += 2;
		assertEquals(0, resp[i] & 0x80);
		i += 1 + resp[i];

		assertEquals(0x7F74, Util.getShort(resp, (short)i));
		i += 2;
		assertEquals(0, resp[i] & 0x80);
		i += 1 + resp[i];

		assertEquals(0x73, resp[i++]);
		assertEquals(0x80, resp[i] & 0x80);
		i += 1 + (resp[i] & 0xf);

		while (i < resp.length - 2) {
			switch (resp[i++]) {
				case (byte)0xC0:
					assertEquals(10, resp[i]);
					break;
				case (byte)0xC1:
				case (byte)0xC2:
				case (byte)0xC3:
					assertEquals(0, resp[i] & 0x80);
					break;
				case (byte)0xC4:
					assertEquals(7, resp[i]);
					break;
				case (byte)0xC5:
				case (byte)0xC6:
					assertEquals(60, resp[i]);
					break;
				case (byte)0xCD:
					assertEquals(12, resp[i]);
					break;
				case (byte)0xD6:
				case (byte)0xD7:
				case (byte)0xD8:
					assertEquals(2, resp[i]);
					break;
				default:
					fail(String.format("Unexpected tag: 0x%02x ", resp[i]));
			}
			i += 1 + resp[i];
		}

		assertEquals(resp.length - 2, i);
	}

	@Test
	public void testReadPrivateDOs() {
		// DOs 1 and 2 are always readable
		// DO 3 requires PW1 (mode 82), DO 4 requires PW3
		byte[] resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x01});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x02});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x03});
		assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x04});
		assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, sw(resp));

		// Verify PW1 mode 81
		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x81, 8,
			'1', '2', '3', '4', '5', '6', (byte)0xff, (byte)0xff,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x03});
		assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x04});
		assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, sw(resp));

		// Verify PW1 mode 82
		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x82, 8,
			'1', '2', '3', '4', '5', '6', (byte)0xff, (byte)0xff,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x03});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x04});
		assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, sw(resp));

		// Verify PW3
		resp = simulator.transmitCommand(new byte[] {
			0x00, 0x20, 0x00, (byte)0x83, 8,
			'1', '2', '3', '4', '5', '6', '7', '8',
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		assertEquals(true, doVerify("12345678", (byte) 0x83));

		resp = simulator.transmitCommand(new byte[] {0, (byte)0xca, 0x01, 0x04});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
	}

	private boolean doVerify(String pin, byte mode) {
		byte[] command = new byte[5 + pin.length()];
		command[0] = 0;
		command[1] = 0x20;
		command[2] = 0;
		command[3] = mode;
		command[4] = (byte)pin.length();
		int offs = 5;
		for(byte b : pin.getBytes()) {
			command[offs++] = b;
		}
		byte[] resp = simulator.transmitCommand(command);
		if (sw(resp) == ISO7816.SW_NO_ERROR) {
			return true;
		} else {
			return false;
		}
	}

	private short sw(byte[] response) {
		int i = response.length - 2;
		return (short)(((response[i] & 0xff) << 8) | (response[i+1] & 0xff));
	}

	private byte[] getPinRetries() {
		byte[] resp = simulator.transmitCommand(new byte[] {
			0, (byte)0xca, 0, (byte)0xc4, 0,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));
		return Arrays.copyOfRange(resp, 4, 7);
	}

	@SuppressWarnings("unused")
	private void dumpHex(byte[] data) {
		String out = "";
		for(byte b : data) {
			out += String.format("0x%02x ", b);
		}
		System.out.println(out);
	}
}
