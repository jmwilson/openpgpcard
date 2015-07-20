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
		byte[] result = new byte[3];
		byte[] resp = simulator.transmitCommand(new byte[] {
			0, (byte)0xca, 0, (byte)0x6e, 0,
		});
		assertEquals(ISO7816.SW_NO_ERROR, sw(resp));

		assertEquals((byte)OpenPGPCard.DO_APPLICATION_DATA, resp[0]);
		int i = 1;
		if ((resp[i] & 0x80) != 0) {
			i += 1 + (resp[i] & 0xf);
		} else {
			i++;
		}
		while (resp[i] != (byte)OpenPGPCard.DO_DISCRETIONARY_DOS) {
			if ((resp[i++] & 0x1f) == 0x1f) {  // bitmask for multibyte tag
				while((resp[i] & 0x80) != 0) {
					i++;
				}
				i++;
			}
			int len = 0;
			if ((resp[i] & 0x80) != 0) {  // multibyte length
				switch (resp[i++] & 0xf) {
					case 2:
						len = resp[i++] & 0xff;  // fall through
					case 1:
						len = (len << 8) | (resp[i++] & 0xff);
				}
			} else {
				len = resp[i++];
			}
			i += len;
		}

		i++;
		if ((resp[i] & 0x80) != 0) {
			i += 1 + (resp[i] & 0xf);
		} else {
			i++;
		}
		while (resp[i] != (byte)OpenPGPCard.DO_PW_STATUS) {
			i++;
			int len = 0;
			if ((resp[i] & 0x80) != 0) {
				switch (resp[i++] & 0xf) {
					case 2:
						len = resp[i++] & 0xff;  // fall through
					case 1:
						len = (len << 8) | (resp[i++] & 0xff);
				}
			} else {
				len = resp[i++];
			}
			i += len;
		}

		i += 6; // tag, length, force signature, 3 x max pin size
		result[0] = resp[i++];
		result[1] = resp[i++];
		result[2] = resp[i++];
		return result;
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
