-repackageclasses 'com.android.internal.util.framework'
-keep class com.android.internal.util.framework.Android {
    public <methods>;
}
-keep class com.android.internal.util.framework.Keybox {
    public static *;
}
-keep class com.android.internal.util.framework.ProfileConfig {
    public static *;
}
