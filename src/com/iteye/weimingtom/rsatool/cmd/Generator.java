package com.iteye.weimingtom.rsatool.cmd;

import org.bouncycastle.openssl.PEMKeyPair;

import com.iteye.weimingtom.rsatool.Pem;

/**
 * Generate PEM file
 */
public class Generator {
	public static void main(String[] args) {
		if (args.length >= 1 && args[0].equals("private")) {
			String privateKey = getPrivateKey();
			String publicKey = getPublicKey(privateKey);
			System.out.println("privateKey = \n" + privateKey);
			System.out.println("publicKey = \n" + publicKey);
		} else if (args.length >= 2 && args[0].equals("public")) {
			String privateKey = Pem.readFileToString(args[1], "UTF-8");
			String publicKey = getPublicKey(privateKey);
			System.out.println("[" + args[1] + "] privateKey = \n" + privateKey);
			System.out.println("publicKey = \n" + publicKey);
		} else {
			System.out.println(Generator.class.getCanonicalName() + 
					" [private | public [file_name]] ");
		}
	}
	
	private static String getPrivateKey() {
		return Pem.genPrivateKeyAndPem(new PEMKeyPair[1]);
	}

	private static String getPublicKey(String privateKey) {
		PEMKeyPair privateKeyPair = Pem.genPrivateKeyByPem(privateKey);
		if (privateKeyPair == null) {
			return "";
		}
		return Pem.genPublickKeyPem(privateKeyPair);	
	}
}
