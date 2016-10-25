package com.iteye.weimingtom.rsatooland;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;

import com.example.rsatooland.R;
import com.iteye.weimingtom.rsatool.cmd.Crypt;

public class Test001Activity extends Activity {
	private static final boolean D = false;
	private static final String TAG = "LoginActivity";	

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		this.setContentView(R.layout.activity_test001);
		//Generator.main(new String[]{"private"});
		Crypt.main(null);
	}
	
	public class CheckUserStatusTask extends AsyncTask<Void, Void, Void> {
		public CheckUserStatusTask() {  
			
		}

		@Override
		protected Void doInBackground(Void... params) {
		   	RestClient.getInstance(Test001Activity.this).getUserStatus(Test001Activity.this, "", new RecvDataListener() {
	   			@Override
				public void onRecvData(boolean successStatus, int statusCode, 
						String responseString, Throwable throwable) {
	    			if (successStatus) {
						if (responseString != null) {
							System.out.println(responseString);
						}
	    			} else {
	    				
	    			}
		    	}
		   	});
			return null;
		}

		@Override
		protected void onPostExecute(Void result_) {
			super.onPostExecute(result_);
		}
	}
}
