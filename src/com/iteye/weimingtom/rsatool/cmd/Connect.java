package com.iteye.weimingtom.rsatool.cmd;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.ClientProtocolException;

import com.iteye.weimingtom.rsatool.ConnectUtil;
import com.iteye.weimingtom.rsatool.Pem;

/**
 * Send encrypted data to server
 * 
 */
public class Connect {
	//http://blog.csdn.net/aa332073044/article/details/20710503
	public static void main(String[] args) throws ClientProtocolException, IOException {
		if (args.length >= 3) {	
			final String baseUrl = args[0];
			Map<String,String> params = new HashMap<String, String>();
			String content = Pem.readFileToString(args[1], "UTF-8");
			System.out.println("request content <= " + content);
			params.put(args[2], Crypt.encrypt(content));
			String str = ConnectUtil.send(baseUrl, params, "UTF-8", true);
			System.out.println("response content => " + str);
		} else {
			System.out.println(Connect.class.getCanonicalName() + 
				" [url] [file_name] [param_name]");
		}
	}
}
