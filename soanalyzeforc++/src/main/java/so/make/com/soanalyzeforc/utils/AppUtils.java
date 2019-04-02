package so.make.com.soanalyzeforc.utils;

import android.os.Environment;

import java.io.File;

/**
 * Created by lyh on 2019/3/18.
 */

public class AppUtils {
    public static String getSDPath(){
        File sdDir = null;
        boolean sdCardExist = Environment.getExternalStorageState()
                .equals(android.os.Environment.MEDIA_MOUNTED);//判断sd卡是否存在
        if(sdCardExist)
        {
            sdDir = Environment.getExternalStorageDirectory();//获取跟目录
        }
        return sdDir.toString();
    }
}
