package com.makelove.soAnalyze;

import android.Manifest;
import android.content.pm.PackageManager;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity implements PermissionCallBack {

    private static String[] PERMISSIONS={
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        PermissionUtils.initPermission(this,PERMISSIONS,this);
    }


    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        int count=0;
        switch (requestCode) {
            case 1:
                for (int i = 0; i < grantResults.length; i++) {
                    if (grantResults[i] != PackageManager.PERMISSION_GRANTED) {
                        //判断是否勾选禁止后不再询问
                        boolean showRequestPermission = ActivityCompat.
                                shouldShowRequestPermissionRationale(this, permissions[i]);
                        if (showRequestPermission) {
                            return;
                        } else {
                            Toast.makeText(getApplicationContext(), "权限",Toast.LENGTH_LONG).show();
                        }
                    }else {
                        //拿到 权限
                        count++;
                    }

                }
                if(count==grantResults.length){
                    //全部拿到
                    SoProcessing();
                }else {
                    //没有全部拿到
//                    ToastUtils.showToast(this,getSectionString(R.string.asdfasd));
//                    System.exit(0);
                }
                //初始化推送
                break;

        }
    }

    private void SoProcessing() {
        String path = Utils.getSDPath() + "/" + "So"+ "/" ;

        byte[] srcByte = Utils.File2bytes(path + "hello.so");

        parseSo(srcByte);




    }

    private void parseSo(byte[] fileByteArys) {





//        //读取头部内容
//        LogUtils.e("+++++++++++++++++++Elf Header+++++++++++++++++");
//        SoParse.parseHeader(fileByteArys, 0);
//
//
//        //读取Program Header
//        LogUtils.e("+++++++++++++++++++Program Header+++++++++++++++++");
//        SoParse.parseProgramHeaderList(fileByteArys);
//
//        LogUtils.e("+++++++++++++++++++Section Header++++++++++++++++++");
//        SoParse.parseSectionHeaderList(fileByteArys);









    }


    @Override
    public void getPermission(boolean isGet) {
        if(isGet){
            SoProcessing();
        }
    }


}
