package so.make.com.soanalyzeforc;

import android.Manifest;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import so.make.com.soanalyzeforc.utils.AppUtils;

public class MainActivity extends AppCompatActivity implements PermissionCallBack{

    private static String[] PERMISSIONS={
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
    };
    static {
        System.loadLibrary("main");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        PermissionUtils.initPermission(this,PERMISSIONS,this);
    }


    @Override
    public void getPermission(boolean isGet) {
        if(isGet) {
            LogUtils.e("我被执行了 ");
            Main();
            LogUtils.e("执行完毕 ");
        }
    }

    public native void Main();
    public native void Test();
}
