package com.ns.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ns.auth.NsAuthInfo;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
/**
 * NS请求工具类
 *
 * @author zhangBaoShine
 * @version 2021-05-28
 */
public class NsRequestUtils {


    /**
     * 发送请求并返回响应结果
     *
     * @param url           请求url
     * @param requestMethod 请求方式
     * @param paramsMap     参数
     * @param authInfo      认证信息
     * @return 请求响应结果
     */
    public static Map<String, Object> executeRequest(String url, String requestMethod, Map<String, Object> paramsMap, NsAuthInfo authInfo) {
        Map<String, Object> resultMap = new HashMap<>();
        try {
            String authorization = NsRequestUtils.constructAuthHeader(authInfo, requestMethod);

            CloseableHttpClient httpClient = HttpClientBuilder.create().build();
            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Accept", "*/*");
            httpPost.setHeader("Authorization", authorization);

            String jsonParams = JSON.toJSONString(paramsMap);
            HttpEntity entityParam = new StringEntity(jsonParams, ContentType.create("application/json", "UTF-8"));
            httpPost.setEntity(entityParam);
            HttpResponse response = httpClient.execute(httpPost);

            // 状态码
            resultMap.put("code", response.getStatusLine().getStatusCode() + "");
            // 返回结果
            resultMap.put("result", EntityUtils.toString(response.getEntity(), "utf-8"));
        } catch (Exception e) {
            resultMap.put("code", "400");
        }

        return resultMap;
    }

    /**
     * 生成签名并组合Authorization头
     * 如"/", 编码后为: %2F
     *
     * @return 编码后的字符串
     */
    public static String constructAuthHeader(NsAuthInfo auth, String method) throws Exception {
        // 基础信息
        String url = auth.getUrl();
        // 时间戳
        long timestamp = new Date().getTime() / 1000;
        // 转成大写
        method = method.toUpperCase();
        // 签名方法
        String signatureMethod = "HMAC-SHA256", signatureMethodCode = "HmacSHA256";
        // 基础信息
        String accessToken = auth.getAccessToken(), tokenSecret = auth.getTokenSecret(),
                consumerKey = auth.getConsumerKey(), consumerSecret = auth.getConsumerSecret(),
                realm = auth.getRealm(), nonce = getRandomStr(32);
        // 组合Key
        String key = consumerSecret + '&' + tokenSecret;
        // 截取问号前的URL
        String encodeURL = url.split("\\?")[0];

        // 获取URL参数
        Map<String, String> parameters = urlSplit(url);
        parameters.put("oauth_consumer_key", consumerKey);
        parameters.put("oauth_nonce", nonce);
        parameters.put("oauth_signature_method", signatureMethod);
        parameters.put("oauth_timestamp", String.valueOf(timestamp));
        parameters.put("oauth_token", accessToken);
        parameters.put("oauth_version", "1.0");
        String parameterString = sortAndConcat(parameters);
        // 组合待签字符串
        StringBuilder signatureBaseString = new StringBuilder(100);
        signatureBaseString.append(method.toUpperCase());
        signatureBaseString.append('&');
        signatureBaseString.append(urlEncode(encodeURL));
        signatureBaseString.append('&');
        signatureBaseString.append(urlEncode(parameterString));
        // 转换成String类型
        String signatureString = signatureBaseString.toString();
        // 生成签名
        byte[] bytesToSign = signatureString.getBytes("UTF-8");
        byte[] keyBytes = key.getBytes("UTF-8");
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, signatureMethodCode);
        Mac mac = Mac.getInstance(signatureMethodCode);
        mac.init(signingKey);
        byte[] signedBytes = mac.doFinal(bytesToSign);
        String signature = urlEncode(new String(Base64.encodeBase64(signedBytes, false)));

        return new StringBuilder().append("OAuth ")
                .append("realm").append("=\"").append(realm)
                .append("\",").append("oauth_consumer_key").append("=\"").append(consumerKey)
                .append("\",").append("oauth_token").append("=\"").append(accessToken)
                .append("\",").append("oauth_signature_method").append("=\"").append(signatureMethod)
                .append("\",").append("oauth_timestamp").append("=\"").append(timestamp)
                .append("\",").append("oauth_nonce").append("=\"").append(nonce)
                .append("\",").append("oauth_version").append("=\"").append("1.0")
                .append("\",").append("oauth_signature").append("=\"").append(signature)
                .append("\"").toString();
    }


    /**
     * 返回参数double的空处理
     *
     * @param jsonObject json对象
     * @param key
     * @return
     */
    public static Double killNullDouble(JSONObject jsonObject, String key) {
        Double result = jsonObject.getDouble(key);
        return result == null ? 0.0D : result;
    }


    /**
     * 解析出url参数中的键值对
     * 如 "restlet.nl?script=248&deploy=1"，解析出script:24,deploy:1存入map中
     *
     * @param URL url地址
     * @return url请求参数部分
     */
    public static Map<String, String> urlSplit(String URL) {
        Map<String, String> mapRequest = new HashMap<String, String>();
        String[] arrSplit = null;
        String strUrlParam = TruncateUrlPage(URL);
        if (strUrlParam == null) {
            return mapRequest;
        }
        arrSplit = strUrlParam.split("[&]");
        for (String strSplit : arrSplit) {
            String[] arrSplitEqual = null;
            arrSplitEqual = strSplit.split("[=]");
            //解析出键值
            if (arrSplitEqual.length > 1) {
                //正确解析
                mapRequest.put(arrSplitEqual[0], arrSplitEqual[1]);
            } else {
                if (arrSplitEqual[0] != "") {
                    //只有参数没有值，不加入
                    mapRequest.put(arrSplitEqual[0], "");
                }
            }
        }
        return mapRequest;
    }

    /**
     * 去掉url中的路径，留下请求参数部分
     *
     * @param strURL url地址
     * @return url请求参数部分
     */
    private static String TruncateUrlPage(String strURL) {
        String strAllParam = null;
        String[] arrSplit = null;
        strURL = strURL.trim().toLowerCase();
        arrSplit = strURL.split("[?]");
        if (strURL.length() > 1) {
            if (arrSplit.length > 1) {
                for (int i = 1; i < arrSplit.length; i++) {
                    strAllParam = arrSplit[i];
                }
            }
        }
        return strAllParam;
    }


    /**
     * 对URL参数进行排序
     * 如"script:248,deploy:1", 排序后deploy=1&script=248
     *
     * @param parameters 参数的键值对
     * @return 排序后的字符串
     */
    private static String sortAndConcat(Map<String, String> parameters) {
        StringBuilder encodedParams = new StringBuilder(100);
        Object[] arr = parameters.keySet().toArray();
        Arrays.sort(arr);
        for (Object key : arr) {
            if (encodedParams.length() > 0) {
                encodedParams.append('&');
            }
            encodedParams.append(key).append('=').append(parameters.get(key));

        }
        return encodedParams.toString();
    }

    /**
     * 对字符串进行URL编码
     * 如"/", 编码后为: %2F
     *
     * @param str 传入字符串
     * @return 编码后的字符串
     */
    private static String urlEncode(String str) {
        try {
            return URLEncoder.encode(str, "UTF-8")
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 获取随机字符串
     *
     * @param count
     * @return
     */
    public static String getRandomStr(int count) {
        char[] codeSeq = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        Random random = new Random();
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < count; i++) {
            String r = String.valueOf(codeSeq[random.nextInt(codeSeq.length)]);
            s.append(r);
        }
        return s.toString();
    }
}
