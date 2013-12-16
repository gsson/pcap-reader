package se.fnord.pcap.internal;

public class Util {
	private Util() {
		throw new IllegalAccessError();
	}

	private static final char[][] INT_LUT = new char[256][];
	static {
		for (int i = 0; i < INT_LUT.length; i++)
			INT_LUT[i] = Integer.toString(i).toCharArray();
	}

	private static int copyIn(final int octet, final char[] dst, final int offset) {
		final char[] n = INT_LUT[octet];
		switch (n.length) {
		case 1:
			dst[offset] = n[0];
			return offset + 1;
		case 2:
			dst[offset] = n[0];
			dst[offset + 1] = n[1];
			return offset + 2;
		case 3:
			dst[offset] = n[0];
			dst[offset + 1] = n[1];
			dst[offset + 2] = n[2];
			return offset + 3;
		}
		throw new IllegalArgumentException();
	}

	public static String toDottedQuad(int address) {
		final char[] s = new char[15];
		int i = 0;

		i = copyIn((address >>> 24) & 0xff, s, i);
		s[i++] = '.';
		i = copyIn((address >>> 16) & 0xff, s, i);
		s[i++] = '.';
		i = copyIn((address >>> 8) & 0xff, s, i);
		s[i++] = '.';
		i = copyIn(address & 0xff, s, i);
		return new String(s, 0, i);
	}
}
