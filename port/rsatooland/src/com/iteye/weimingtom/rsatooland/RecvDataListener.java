package com.iteye.weimingtom.rsatooland;

public abstract class RecvDataListener {
	public abstract void onRecvData(boolean successStatus, int statusCode, 
		String responseString, Throwable throwable);
	
	public void onProgress(int bytesWritten, int totalSize) {
		
	}
}
