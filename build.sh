APK_PATH="bin/JustTrustMe.apk"
mkdir bin
./gradlew assembleRelease && cp app/build/outputs/apk/app-release-unsigned.apk $APK_PATH && signapk $APK_PATH

#adb install -r bin/AndroidVTS.apk
