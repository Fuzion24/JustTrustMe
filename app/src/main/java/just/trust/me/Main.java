package just.trust.me;

import org.apache.http.conn.ssl.SSLSocketFactory;

import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;


import static de.robv.android.xposed.XposedHelpers.findMethodExact;


public class Main implements IXposedHookLoadPackage {


    abstract class XposedMethodReplacement extends XC_MethodReplacement
    {
        public XposedMethodReplacement(){}
        Method replacedMethod;
        public void setReplacedMethod(Method m){
            replacedMethod = m;
        }

    }

    public static XC_MethodHook.Unhook findAndHookMethod(String clazz, java.lang.ClassLoader classLoader, String methodName, XposedMethodReplacement xmp) {
        Method m = findMethodExact(clazz, classLoader, methodName);
        xmp.setReplacedMethod(m);
        return XposedBridge.hookMethod(m, xmp);
    }


    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {

        findAndHookMethod("javax.net.ssl.TrustManagerFactory", lpparam.classLoader, "getTrustManagers", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return new TrustManager[]{new ImSureItsLegitTrustManager()};
            }
        });

        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setSSLSocketFactory", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{new ImSureItsLegitTrustManager()}, null);
                this.replacedMethod.invoke(param.thisObject, context.getSocketFactory());
                return null;
            }
        });

        findAndHookMethod("javax.net.ssl.SSLContext", lpparam.classLoader, "init", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{new ImSureItsLegitTrustManager()}, null);
                this.replacedMethod.invoke(param.thisObject, null, new TrustManager[]{new ImSureItsLegitTrustManager()}, null);
                return null;
            }
        });

        findAndHookMethod("org.apache.http.conn.ssl.SSLSocketFactory", lpparam.classLoader, "isSecure", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return true;
            }
        });

        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setHostnameVerifier", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                this.replacedMethod.invoke(param.thisObject, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                return null;
            }
        });

        findAndHookMethod("javax.net.ssl.HttpsURLConnection", lpparam.classLoader, "setDefaultHostnameVerifier", new XposedMethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                this.replacedMethod.invoke(param.thisObject, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                return null;
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
