package com.vs.vpn

object NativeLib {
    init {
        System.loadLibrary("vs_vpn_jni")
    }

    /** Запускает прокси. Возвращает порт (>0) при успехе, -1 при ошибке, -2 если уже запущен. */
    external fun nativeStart(server: String, secret: String?, listen: String): Int

    /** Останавливает прокси. Возвращает true, если прокси был запущен и остановлен. */
    external fun nativeStop(): Boolean

    /** Вычитывает накопившиеся логи (одна строка, строки разделены \n). Буфер очищается. */
    external fun nativePollLogs(): String
}
