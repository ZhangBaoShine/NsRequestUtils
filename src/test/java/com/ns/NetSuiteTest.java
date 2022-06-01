package com.ns;

import com.ns.auth.NsAuthInfo;
import com.ns.utils.NsConstant;
import com.ns.utils.NsRequestUtils;
import jdk.nashorn.internal.ir.annotations.Ignore;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

@Ignore
public class NetSuiteTest {
    @Test
    public void test1() {
        // 参数放置
        Map<String, Object> paramsMap = new HashMap<>();
        // 请求方法名
        String url = NsConstant.URL + "&script=1255";
        // 构建认证信息
        NsAuthInfo authInfo = new NsAuthInfo(NsConstant.REALM, url, NsConstant.ACCESS_TOKEN, NsConstant.TOKEN_SECRET,
                NsConstant.CONSUMER_KEY, NsConstant.CONSUMER_SECRET);

        Map<String, Object> result = NsRequestUtils.executeRequest(url, "POST", paramsMap, authInfo);
        System.out.println(result);
    }
}
