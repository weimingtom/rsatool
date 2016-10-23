package com.iteye.weimingtom.rsatool;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Use PEMKeyPair to encrypt data
 *
 */
public class Pem {
	private final static int RsaBit = 1024;
	
	private static Provider provider = new BouncyCastleProvider();
	static {
		Security.addProvider(provider);
	}
	
	public static String genPrivateKeyAndPem(PEMKeyPair[] privateKey) {
		StringWriter writer = new StringWriter();
		KeyPair kp = null;
		JcaPEMWriter pemWriter = null;
		try {
			SecureRandom rand = new SecureRandom();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
	        kpg.initialize(RsaBit, rand);
	        kp = kpg.generateKeyPair();
	        
			pemWriter = new JcaPEMWriter(writer);
			pemWriter.writeObject(kp);
			pemWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} finally {
			if (pemWriter != null) {
				try {
					pemWriter.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		String result = writer.toString();
		if (writer != null) {
			try {
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		Reader reader = new StringReader(result);
		PEMParser pemReader = new PEMParser(reader);
		PEMKeyPair kp2 = null;
		try {
			kp2 = (PEMKeyPair)pemReader.readObject();
	        if (privateKey != null && privateKey.length > 0) {
	        	privateKey[0] = kp2;
	        }
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	public static String genPublickKeyPem(PEMKeyPair kp) {
		if (kp == null) {
			return "";
		}
		SubjectPublicKeyInfo publicKey = kp.getPublicKeyInfo();
		
		//http://stackoverflow.com/questions/15823094/rsa-bouncycastle-pemreader-returning-pemkeypair-instead-of-asymmetriccipherkey
		StringWriter writer = new StringWriter();
		PemWriter pemWriter = null;
		try {
			pemWriter = new PemWriter(writer);
			pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
			pemWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (pemWriter != null) {
				try {
					pemWriter.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return writer.toString();
	}
	
	public static PEMKeyPair genPrivateKeyByPem(String pemstr) {
		Reader reader = new StringReader(pemstr);
		PEMParser pemReader = new PEMParser(reader);
		PEMKeyPair kp = null;
		try {
			kp = (PEMKeyPair)pemReader.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return kp;
	}
	
	public static String readFileToString(String filename, String charset) {
		InputStream is = null;
		StringBuilder sb = new StringBuilder();
		String line = null;
		try {
			is = new FileInputStream(filename);
			BufferedReader reader = new BufferedReader(new InputStreamReader(is, charset));
			while ((line = reader.readLine()) != null) {
				sb.append(line + "\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return sb.toString();
	}
	
	
	
	//============================
	
	public static boolean verifySig(byte[] data, byte[] sig, 
		SubjectPublicKeyInfo publickKey) {
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		try {
			PublicKey key = converter.getPublicKey(publickKey);
			Signature md5WithRsa = Signature.getInstance("MD5withRSA", BouncyCastleProvider.PROVIDER_NAME);
			md5WithRsa.initVerify(key);
			md5WithRsa.update(data);
			if (!md5WithRsa.verify(sig)) {
				return false;
			}
			return true;
		} catch (PEMException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	//https://github.com/coolzyt/yuntaoframework/blob/master/src/main/java/org/yuntao/framework/tool/secure/RsaTool.java
	public static byte[] sig(PEMKeyPair privateKey, byte[] tosig) {
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		try {
			KeyPair key = converter.getKeyPair(privateKey);
			Signature md5WithRsa = Signature.getInstance("MD5withRSA", BouncyCastleProvider.PROVIDER_NAME);
			md5WithRsa.initSign(key.getPrivate());
			md5WithRsa.update(tosig);
			return md5WithRsa.sign();
		} catch (PEMException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return new byte[0];
	}
	
	
	public static String encrypt(String plainText, PEMKeyPair privateKey) throws Exception {  
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		PublicKey key = converter.getPublicKey(privateKey.getPublicKeyInfo());
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
			byte[] bytes = Base64.encode(bytesEnc != null ? bytesEnc : new byte[0]);
			return bytes != null ? new String(bytes, "UTF-8") : "";
		} catch (Exception e) {
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
	
	public static String decrypt(String content, PEMKeyPair privateKey) throws Exception {
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		//PublicKey publicKey = converter.getPublicKey(privateKey.getPublicKeyInfo());
		PrivateKey key = converter.getPrivateKey(privateKey.getPrivateKeyInfo());
		InputStream ins = null;
		ByteArrayOutputStream writer = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) key);
			int blockLen = ((RSAKey) key).getModulus().bitLength() / 8; // 128
			byte[] bytes = Base64.decode(content != null ? content.getBytes("UTF-8") : new byte[0]);
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
}
