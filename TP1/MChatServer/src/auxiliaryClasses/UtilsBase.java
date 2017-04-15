package auxiliaryClasses;

/**
 * Classe auxiliar
 */
public class UtilsBase {
	private static String digits = "0123456789abcdef";

	/**
	 * Retorna string hexadecimal a partir de um byte array de certo tamanho
	 * 
	 * @param data
	 *            : bytes a coverter
	 * @param length
	 *            : numero de bytes no bloco de dados a serem convertidos.
	 * @return hex : representacaop em hexadecimal dos dados
	 */

	public static String toHex(byte[] data, int length) {
		StringBuffer buf = new StringBuffer();

		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;

			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}

		return buf.toString();
	}

	/**
	 * Retorna dados passados como byte array numa string hexadecimal
	 * 
	 * @param data
	 *            : bytes a serem convertidos
	 * @return : representacao hexadecimal dos dados.
	 */
	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}

	/**
	 * 
	 * @param buffer
	 * @return string em array de bytes
	 */
	public static byte[] stringToByteArray(String buffer) {
		return buffer.getBytes();
	}
	
	/**
	 * 
	 * @param s
	 * @return
	 */
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
}
