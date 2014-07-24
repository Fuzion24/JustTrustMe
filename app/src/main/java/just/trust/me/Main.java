package just.trust.me;


import android.util.Log;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;


import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class Main implements IXposedHookLoadPackage {

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {

        findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return new TrustManager[]{new ImSureItsLegitTrustManager()};
            }
        });

        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{new ImSureItsLegitTrustManager()}, null);
                return null;
            }
        });

        findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return true;
            }
        });

        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return true;
            }
        });
    }

    class ImSureItsLegitTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
