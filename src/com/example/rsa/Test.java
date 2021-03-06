package com.example.rsa;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @see http://blog.csdn.net/bbld_/article/details/38777491
 * @see http://blog.csdn.net/jdsjlzx/article/details/41441147
 */
public class Test {
	private static String PUCLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCfRTdcPIH10gT9f31rQuIInLwe"
			+ "\r" + "7fl2dtEJ93gTmjE9c2H+kLVENWgECiJVQ5sonQNfwToMKdO0b3Olf4pgBKeLThra" + "\r"
			+ "z/L3nYJYlbqjHC3jTjUnZc0luumpXGsox62+PuSGBlfb8zJO6hix4GV/vhyQVCpG" + "\r"
			+ "9aYqgE7zyTRZYX9byQIDAQAB" + "\r";
	private static String PRIVATE_KEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ9FN1w8gfXSBP1/"
			+ "\r" + "fWtC4gicvB7t+XZ20Qn3eBOaMT1zYf6QtUQ1aAQKIlVDmyidA1/BOgwp07Rvc6V/" + "\r"
			+ "imAEp4tOGtrP8vedgliVuqMcLeNONSdlzSW66alcayjHrb4+5IYGV9vzMk7qGLHg" + "\r"
			+ "ZX++HJBUKkb1piqATvPJNFlhf1vJAgMBAAECgYA736xhG0oL3EkN9yhx8zG/5RP/" + "\r"
			+ "WJzoQOByq7pTPCr4m/Ch30qVerJAmoKvpPumN+h1zdEBk5PHiAJkm96sG/PTndEf" + "\r"
			+ "kZrAJ2hwSBqptcABYk6ED70gRTQ1S53tyQXIOSjRBcugY/21qeswS3nMyq3xDEPK" + "\r"
			+ "XpdyKPeaTyuK86AEkQJBAM1M7p1lfzEKjNw17SDMLnca/8pBcA0EEcyvtaQpRvaL" + "\r"
			+ "n61eQQnnPdpvHamkRBcOvgCAkfwa1uboru0QdXii/gUCQQDGmkP+KJPX9JVCrbRt" + "\r"
			+ "7wKyIemyNM+J6y1ZBZ2bVCf9jacCQaSkIWnIR1S9UM+1CFE30So2CA0CfCDmQy+y" + "\r"
			+ "7A31AkB8cGFB7j+GTkrLP7SX6KtRboAU7E0q1oijdO24r3xf/Imw4Cy0AAIx4KAu" + "\r"
			+ "L29GOp1YWJYkJXCVTfyZnRxXHxSxAkEAvO0zkSv4uI8rDmtAIPQllF8+eRBT/deD" + "\r"
			+ "JBR7ga/k+wctwK/Bd4Fxp9xzeETP0l8/I+IOTagK+Dos8d8oGQUFoQJBAI4Nwpfo" + "\r"
			+ "MFaLJXGY9ok45wXrcqkJgM+SN6i8hQeujXESVHYatAIL/1DgLi+u46EFD69fw0w+" + "\r" + "c7o0HLlMsYPAzJw="
			+ "\r";
	
	public static void main(String[] args) {
		String plainText = "123456";
		System.out.println("plainText => " + plainText);
		String content = test1(plainText);
		test2(content);
	}

	private static String test1(String source) {
		source = source.trim();
		try {
			// PublicKey publicKey = RSAUtils.loadPublicKey(PUCLIC_KEY);
			InputStream inPublic = new FileInputStream("rsa_public_key.pem");
			PublicKey publicKey = RSAUtils.loadPublicKey(inPublic);
			byte[] encryptByte = RSAUtils.encryptData(source.getBytes(), publicKey);
			String afterencrypt = Base64Utils.encode(encryptByte);
			System.out.println("afterencrypt => " + afterencrypt);
			return afterencrypt;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	
	private static String test2(String encryptContent) {
		encryptContent = encryptContent.trim();
		try {
			// PrivateKey privateKey = RSAUtils.loadPrivateKey(PRIVATE_KEY);
			InputStream inPrivate = new FileInputStream("pkcs8_rsa_private_key.pem");
			PrivateKey privateKey = RSAUtils.loadPrivateKey(inPrivate);
			byte[] decryptByte = RSAUtils.decryptData(Base64Utils.decode(encryptContent), privateKey);
			String decryptStr = new String(decryptByte);
			System.out.println("decryptStr => " + decryptStr);
			return decryptStr;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
}
