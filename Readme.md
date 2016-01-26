JustTrustMe
===========

An xposed module that disables SSL certificate checking.  This is useful for auditing an appplication which does certificate pinning.  You can read about the practice of cert pinning [here](https://viaforensics.com/resources/reports/best-practices-ios-android-secure-mobile-development/41-certificate-pinning/). There also exists a nice framework built by @moxie to aid in pinning certs in your app: [certificate pinning](https://github.com/moxie0/AndroidPinning). 

An example of an application that does cert pinning is [Twitter](https://play.google.com/store/apps/details?id=com.twitter.android).  If you would like to view the network traffic for this application, you must disable the certificate pinning.

I built this for xposed rather than cydia substrate because xposed seems to support newer devices better. Marc Blanchou wrote the [original tool](https://github.com/iSECPartners/Android-SSL-TrustKiller) for cydia substrate.  If you find that you are not able to MITM an application please file an issue.

## Installation

As a prequsite, your device must be rooted and the xposed framework must be installed.
You can download the xposed framework [here](http://repo.xposed.info/module/de.robv.android.xposed.installer).

### Install from binary

The JustTrustMe binary can be downloaded from [https://github.com/Fuzion24/JustTrustMe/releases/latest](https://github.com/Fuzion24/JustTrustMe/releases/latest)

```
adb install ./JustTrustMe.apk
```

or navigate here and download the APK on your phone:
[https://github.com/Fuzion24/JustTrustMe/releases/latest](https://github.com/Fuzion24/JustTrustMe/releases/latest)


### Build from Source
All the normal gradle build commands apply:
To build a release APK:
```
./gradlew assembleRelease
```
To install directly to the phone connected via ADB:
```
./gradlew installRelease
```



