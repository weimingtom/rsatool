package com.iteye.weimingtom.rsatool.cmd;

import com.iteye.weimingtom.rsatool.RsaKey;

/**
 * Encrypt / Decrpyt data
 * 
 */
public class Crypt {
	private static final String privateKey = 
"-----BEGIN RSA PRIVATE KEY-----\n" +
"MIICXAIBAAKBgQCzOPMC9B3R7TAEqLU3kZlP/TIl+TdbetmL7UMzbEYfds9kFQab\n" +
"6AGTxFn+9XrPqTamhLq8WVm1RRJQlDxZvt/EvlbVsyD3aGfMlGd+FPXPcRbvE53+\n" +
"kcXrStK4rogmsDNPIL5qWoc0iv4xdJGkImWxvJmZpDY9sTYr6dxCiuwxmQIDAQAB\n" +
"AoGAHTrGA27N6D1vTes39vKjlvSb966AFUbhcR1Gjv3zJ9GIPHHjbIz3qOJmrRrb\n" +
"J0AZPio6jFpkM5iqxoKOnzJuqxEbvV9t+mdFPtPA+GNXKlRt9N87lozniV8T+TLL\n" +
"qsZNj6CnG9kzO29UnBAxEsBREmuIgb864ljs0ntT3u/eJTMCQQDqRgowHwnUeCFk\n" +
"1mFmVScX/y6BUSY8l+fzOzMtKu+hVfSpK/rKXznQHJ0MpmOuDiFXwARlzpoWHELM\n" +
"120PfSAjAkEAw9fsgAqK26RRC9xc089n5MetSVKQA1AvOsVF8em4xvrQk4FSoolf\n" +
"cT4qLReTDVI3oQ1uHTrG7Rfjk7xEogdlEwJBAK/hmXB7PPQIpHmCAWnEcC8x44Yu\n" +
"mFhRa1BOl6NHYtRrJd2EKSqZx1uYv8dpe9iGvz2T6TlNnJ0Q5o3HBhfkxqUCQAJV\n" +
"d2cLOR5m9eRLSvvnM9jBHGqMRlUTxoxPv4ajf2U3pfasCt0PAAkscXo6FrGI8krE\n" +
"CzTj92zp5PdkvfikV+sCQC70A7N/l3UQ9vGrCHXne7p/2MPkGZrrF0KwotNgyJJk\n" +
"yh1Q4MoXQBTr47rdRyOpwfHN4DnfxRQSnIN95Gwlmes=\n" +
"-----END RSA PRIVATE KEY-----\n";
	
	private static final String publicKey = 
"-----BEGIN PUBLIC KEY-----\n" +
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzOPMC9B3R7TAEqLU3kZlP/TIl\n" +
"+TdbetmL7UMzbEYfds9kFQab6AGTxFn+9XrPqTamhLq8WVm1RRJQlDxZvt/EvlbV\n" +
"syD3aGfMlGd+FPXPcRbvE53+kcXrStK4rogmsDNPIL5qWoc0iv4xdJGkImWxvJmZ\n" +
"pDY9sTYr6dxCiuwxmQIDAQAB\n" +
"-----END PUBLIC KEY-----\n";
	
	public static void main(String[] args) {
		RsaKey myKey2 = new RsaKey(RsaKey.getPublicKeyFromPrivatePemString(privateKey), false);
		String cipher = myKey2.encrypt("123456");
		RsaKey myKey = new RsaKey(RsaKey.getPrivateKeyFromPrivatePemString(privateKey), true);
		String plain = myKey.decrypt(cipher);
		System.out.println("cipher = " + cipher);
		System.out.println("plain = " + plain);
	}

	public static String encrypt(String plain) {
		RsaKey myKey2 = new RsaKey(RsaKey.getPublicKeyFromPrivatePemString(privateKey), false);
		String cipher = myKey2.encrypt(plain);
		return cipher;
	}
	
	public static String decrpyt(String cipher) {
		RsaKey myKey = new RsaKey(RsaKey.getPrivateKeyFromPrivatePemString(privateKey), true);
		String plain = myKey.decrypt(cipher);
		return plain;
	}
}
