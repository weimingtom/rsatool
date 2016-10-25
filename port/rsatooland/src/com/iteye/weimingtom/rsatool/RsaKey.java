package com.iteye.weimingtom.rsatool;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import com.iteye.weimingtom.apache.commons.codec.binary.Base64;
import com.iteye.weimingtom.bouncycastle.asn1.ASN1Object;
import com.iteye.weimingtom.bouncycastle.asn1.ASN1Primitive;
import com.iteye.weimingtom.bouncycastle.asn1.ASN1Sequence;
import com.iteye.weimingtom.bouncycastle.asn1.pkcs.RSAPrivateKey;

/**
 * Use JCA Key (PublicKey / PrivateKey) to encrypt data
 *
 */
public class RsaKey {
	private Key key;
	private boolean isPrivateKey;

	public RsaKey(Key key, boolean isPrivateKey) {
		this.key = key;
		this.isPrivateKey = isPrivateKey;
	}
	
	public Key getKey() {
		return key;
	}

	public void setKey(Key key) {
		this.key = key;
	}

	public boolean isPrivateKey() {
		return isPrivateKey;
	}
	
	public void setPrivateKey(boolean isPrivateKey) {
		this.isPrivateKey = isPrivateKey;
	}
	
	public byte[] sign(byte[] bytes) {
		if (!isPrivateKey) {
			System.out.println("Execption sign error key is not Privatekey...............");
			return null;
		}
		try {
			Signature sign = Signature.getInstance("MD5withRSA");
			sign.initSign((PrivateKey) key);
			sign.update(bytes);
			return sign.sign();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Execption RsaKey sign error...............");
		}
		return null;
	}
	
    public boolean verify(byte[] data, byte[] signedData){
        try{
            Signature sign = Signature.getInstance("MD5withRSA");
            sign.initVerify((PublicKey)key);
            sign.update(data);
            return sign.verify(signedData);
        } catch (Exception e) {
        	e.printStackTrace();
            System.out.println("Execption RsaKey sign error...............");
        }
        return false;
    }
    
	// https://github.com/dancingpudge/cryption-Demo/blob/master/src/main/java/cryption/utils/RSA.java
	public String encrypt(String plainText) {
		InputStream ins = null;
		ByteArrayOutputStream writer = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) key);
			int blockLen = ((RSAKey)key).getModulus().bitLength() / 8 - 11; // 117
			writer = new ByteArrayOutputStream();
			ins = new ByteArrayInputStream(plainText.getBytes("utf-8"));
			byte[] buf = new byte[blockLen];
			while (true) {
				int i = ins.read(buf, 0, blockLen);
				if (i == -1) {
					break;
				}
				cipher.update(buf,0,i);
				writer.write(cipher.doFinal());
				if (i < blockLen) {
					break;
				}
			}
			byte[] bytesEnc = writer.toByteArray();
			byte[] bytes = Base64.encodeBase64(bytesEnc != null ? bytesEnc : new byte[0]);
			return bytes != null ? new String(bytes, "UTF-8") : "";
		} catch (Exception e) {
			System.out.println("Execption RsaKey getCipher error...............");
			e.printStackTrace();
		} finally {
			if (writer != null) {
				try {
					writer.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return "";
	}
  	
	public String decrypt(String content) {
		if (!isPrivateKey) {
			System.out.println("Execption sign error key is not Privatekey...............");
			return null;
		}
		InputStream ins = null;
		ByteArrayOutputStream writer = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) key);
			int blockLen = ((RSAKey) key).getModulus().bitLength() / 8; // 128
			byte[] bytes = Base64.decodeBase64(content != null ? content.getBytes("UTF-8") : new byte[0]);
			ins = new ByteArrayInputStream(bytes);
			writer = new ByteArrayOutputStream();
			byte[] buf = new byte[blockLen];
			while (true) {
				int i = ins.read(buf, 0, blockLen);
				if (i == -1) {
					break;
				}
				cipher.update(buf, 0, i);
				writer.write(cipher.doFinal());
				if (i < blockLen) {
					break;
				}
			}
			return new String(writer.toByteArray(), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Execption RsaKey getPlain error...............");
		} finally {
			if (writer != null) {
				try {
					writer.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return "";
	}
	
	//====================================
	
	public static byte[] readPemFromFile(File pem) throws IOException {
		BufferedReader br = null;
		br = new BufferedReader(new FileReader(pem));
		String s = br.readLine();
		String str = "";
		s = br.readLine();
		while (s.charAt(0) != '-') {
			str += s + "\r";
			s = br.readLine();
		}
		byte[] b = Base64.decodeBase64(str.getBytes("UTF-8"));
		return b;
	}
	
	public static PublicKey getPublicKeyFromPublicPemFile(File filePublicKey) {
		try {
			byte[] b = readPemFromFile(filePublicKey);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
			return kf.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}    
    
    public static PrivateKey getPrivateKeyFromPrivatePemFile(File filePrivatePem) {        
	    //http://stackoverflow.com/questions/6559272/algid-parse-error-not-a-sequence    
    	try {
    		byte[] b = readPemFromFile(filePrivatePem);
			ASN1Sequence as = (ASN1Sequence) ASN1Sequence.fromByteArray(b);
			//RSAPrivateKeyStructure struct = new RSAPrivateKeyStructure(as);
			RSAPrivateKey struct = RSAPrivateKey.getInstance(as);
			RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
					struct.getModulus(), struct.getPublicExponent(),
					struct.getPrivateExponent(), struct.getPrime1(),
					struct.getPrime2(), struct.getExponent1(),
					struct.getExponent2(), struct.getCoefficient());
			KeyFactory factory = KeyFactory.getInstance("RSA");
			return factory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
    }

	public static PublicKey getPublicKeyFromPrivatePemFile(File filePrivatePem) {
		try {
	    	byte[] b = readPemFromFile(filePrivatePem);
			ASN1Sequence as = (ASN1Sequence) ASN1Sequence.fromByteArray(b);
			//RSAPrivateKeyStructure struct = new RSAPrivateKeyStructure(as);
			RSAPrivateKey struct = RSAPrivateKey.getInstance(as);
			RSAPublicKeySpec keySpec2 = new RSAPublicKeySpec(struct.getModulus(),
					struct.getPublicExponent());
			KeyFactory factory = KeyFactory.getInstance("RSA");
			return factory.generatePublic(keySpec2);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	//========================================
	
	public static byte[] readPemFromString(String strPem) throws IOException {
		BufferedReader br = null;
		br = new BufferedReader(new StringReader(strPem));
		String s = br.readLine();
		String str = "";
		s = br.readLine();
		while (s.charAt(0) != '-') {
			str += s + "\r";
			s = br.readLine();
		}
		byte[] b = Base64.decodeBase64(str.getBytes("UTF-8"));
		return b;
	}
	
	public static PublicKey getPublicKeyFromPublicPemString(String strPublicPem) {
		if (strPublicPem == null) {
			strPublicPem = "";
		}
		try {
			byte[] b = readPemFromString(strPublicPem);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
			return kf.generatePublic(keySpec);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static PublicKey getPublicKeyFromPrivatePemString(String str) {
		if (str == null) {
			str = "";
		}
		try {
			byte[] b = readPemFromString(str);
			ASN1Object kk = new ASN1Object() {
				@Override
				public ASN1Primitive toASN1Primitive() {
					return null;
				}
			};
			kk.toASN1Object();
			ASN1Sequence as = (ASN1Sequence) ASN1Primitive.fromByteArray(b);
			//RSAPrivateKeyStructure struct = new RSAPrivateKeyStructure(as);
			RSAPrivateKey struct = RSAPrivateKey.getInstance(as);
			RSAPublicKeySpec keySpec2 = new RSAPublicKeySpec(struct.getModulus(),
					struct.getPublicExponent());
			KeyFactory factory = KeyFactory.getInstance("RSA");
			return factory.generatePublic(keySpec2);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static PrivateKey getPrivateKeyFromPrivatePemString(String strPrivatePem) {
		if (strPrivatePem == null) {
			strPrivatePem = "";
		}
		try {
			byte[] b = readPemFromString(strPrivatePem);
			ASN1Sequence as = (ASN1Sequence) ASN1Sequence.fromByteArray(b);
			//RSAPrivateKeyStructure struct = new RSAPrivateKeyStructure(as);
			RSAPrivateKey struct = RSAPrivateKey.getInstance(as);
			RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
					struct.getModulus(), struct.getPublicExponent(),
					struct.getPrivateExponent(), struct.getPrime1(),
					struct.getPrime2(), struct.getExponent1(),
					struct.getExponent2(), struct.getCoefficient());
			KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePrivate(keySpec);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
}
