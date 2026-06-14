package com.vs.vpn

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.Dispatchers

data class ProxyStatus(
    val isRunning: Boolean = false,
    val port: Int = 0,
    val server: String = "",
    val secret: String? = null,
    val listen: String = "127.0.0.1:1080",
    val logs: List<String> = emptyList()
)

object ProxyManager {
    private const val MAX_LOG_ENTRIES = 128

    private val _status = MutableStateFlow(ProxyStatus())
    val status: StateFlow<ProxyStatus> = _status.asStateFlow()

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var pollingJob: Job? = null

    @Volatile
    var isRunning: Boolean = false
        private set

    /**
     * Запускает SOCKS5-прокси.
     * @return порт при успехе, -1 при ошибке, -2 если уже запущен.
     */
    fun start(server: String, secret: String?, listen: String): Int {
        if (isRunning) return -2

        val port = NativeLib.nativeStart(server, secret, listen)
        if (port > 0) {
            isRunning = true
            _status.update {
                ProxyStatus(
                    isRunning = true,
                    port = port,
                    server = server,
                    secret = secret,
                    listen = listen,
                    logs = emptyList()
                )
            }
            startPolling()
        }
        return port
    }

    /** Останавливает прокси. */
    fun stop() {
        if (!isRunning) return

        pollingJob?.cancel()
        pollingJob = null
        NativeLib.nativeStop()
        isRunning = false
        _status.update { it.copy(isRunning = false, port = 0) }
    }

    private fun startPolling() {
        pollingJob = scope.launch {
            while (isActive) {
                val raw = NativeLib.nativePollLogs()
                if (raw.isNotEmpty()) {
                    val newLines = raw.split("\n").filter { it.isNotBlank() }
                    if (newLines.isNotEmpty()) {
                        _status.update { current ->
                            current.copy(logs = (current.logs + newLines).takeLast(MAX_LOG_ENTRIES))
                        }
                    }
                }
                delay(500)
            }
        }
    }
}
