package com.iteye.weimingtom.rsatooland;

import org.apache.http.Header;
import org.apache.http.client.CookieStore;

import android.content.Context;

import com.loopj.android.http.AsyncHttpResponseHandler;
import com.loopj.android.http.PersistentCookieStore;
import com.loopj.android.http.RequestParams;
import com.loopj.android.http.SyncHttpClient;
import com.loopj.android.http.TextHttpResponseHandler;

public class RestClient {
	private static RestClient mInstance = null;
	private SyncHttpClient client;
	private CookieStore mCookieStore;

	private final static String USER_STATUS_URL = "/";
	private static final String CONTENT_ENCODING = "utf-8";
	
	public static RestClient getInstance(Context context) {
		if (mInstance == null) {
			mInstance = new RestClient();
			mInstance.client = new SyncHttpClient();
			mInstance.client.setEnableRedirects(true);
			mInstance.client.setTimeout(3000);
			mInstance.client.setMaxRetriesAndTimeout(1, 3000);
			mInstance.client.setCookieStore(new PersistentCookieStore(context));
		}
		return mInstance;
	}
	
	private String getAbsoluteUrl(Context context, String relativeUrl) {
        return relativeUrl;
    }
	
    private void get(Context context, int flag, String url, RequestParams params, 
    		AsyncHttpResponseHandler responseHandler) {
        String fullurl = getAbsoluteUrl(context, url);
    	client.get(fullurl, params, responseHandler);
    }
    
    private void post(Context context, int flag, String url, RequestParams params, 
    		AsyncHttpResponseHandler responseHandler) {
    	String fullurl = getAbsoluteUrl(context, url);
    	client.post(fullurl, params, responseHandler);
    }
    
    public void getUserStatus(Context context, String content,
			final RecvDataListener responseHandler) {
		RequestParams params = new RequestParams();
		params.setContentEncoding(CONTENT_ENCODING);
		params.put("content", content);
		post(context, 0, USER_STATUS_URL, null, new TextHttpResponseHandler() {
			@Override
			public void onSuccess(int statusCode, Header[] headers,
					String responseString) {
				responseHandler.onRecvData(true, statusCode, responseString, null);
			}
			
			@Override
			public void onFailure(int statusCode, Header[] headers,
					String responseString, Throwable throwable) {
				responseHandler.onRecvData(false, statusCode, responseString, throwable);
			}
		});
	}
}
