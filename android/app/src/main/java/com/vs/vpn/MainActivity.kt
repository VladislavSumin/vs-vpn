package com.vs.vpn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.vs.vpn.ui.theme.VsVpnTheme

class MainActivity : ComponentActivity() {

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) requestStartProxy()
        }

    private lateinit var settings: SettingsManager

    // Текущие настройки из UI (сохраняются в композиции)
    private var currentServer = ""
    private var currentSecret: String? = null
    private var currentListen = "127.0.0.1:1080"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = SettingsManager(this)
        currentServer = settings.server
        currentSecret = settings.secret.ifBlank { null }
        currentListen = settings.listen

        setContent {
            VsVpnTheme {
                ProxyScreen(
                    initialServer = currentServer,
                    initialSecret = currentSecret,
                    initialListen = currentListen,
                    onStartProxy = { server, secret, listen ->
                        currentServer = server
                        currentSecret = secret
                        currentListen = listen
                        settings.server = server
                        settings.secret = secret ?: ""
                        settings.listen = listen
                        checkPermissionAndStart()
                    },
                    onStopProxy = { stopProxy() }
                )
            }
        }
    }

    private fun checkPermissionAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        requestStartProxy()
    }

    private fun requestStartProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_START
            putExtra(ProxyService.EXTRA_SERVER, currentServer)
            putExtra(ProxyService.EXTRA_SECRET, currentSecret)
            putExtra(ProxyService.EXTRA_LISTEN, currentListen)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
    }
}

@Composable
fun ProxyScreen(
    initialServer: String = "",
    initialSecret: String? = null,
    initialListen: String = "127.0.0.1:1080",
    onStartProxy: (server: String, secret: String?, listen: String) -> Unit,
    onStopProxy: () -> Unit
) {
    val status by ProxyManager.status.collectAsState()

    var serverAddr by remember { mutableStateOf(initialServer) }
    var secretKey by remember { mutableStateOf(initialSecret ?: "") }
    var listenAddr by remember { mutableStateOf(initialListen) }
    val logListState = rememberLazyListState()

    // Автопрокрутка логов вниз при появлении новых строк
    LaunchedEffect(status.logs.size) {
        if (status.logs.isNotEmpty()) {
            logListState.animateScrollToItem(status.logs.size - 1)
        }
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            Text(
                text = "vs-vpn SOCKS5 Proxy",
                style = MaterialTheme.typography.titleMedium
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = serverAddr,
                onValueChange = { serverAddr = it },
                label = { Text("Server address") },
                placeholder = { Text("10.0.0.1:9090") },
                singleLine = true,
                enabled = !status.isRunning,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = secretKey,
                onValueChange = { secretKey = it },
                label = { Text("Secret key (hex, 64 chars, optional)") },
                placeholder = { Text("a1b2... (64 hex chars)") },
                singleLine = true,
                enabled = !status.isRunning,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
            )

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = listenAddr,
                onValueChange = { listenAddr = it },
                label = { Text("Listen address") },
                singleLine = true,
                enabled = !status.isRunning,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = {
                    if (status.isRunning) {
                        onStopProxy()
                    } else {
                        onStartProxy(
                            serverAddr,
                            secretKey.ifBlank { null },
                            listenAddr
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (status.isRunning)
                        MaterialTheme.colorScheme.error
                    else
                        MaterialTheme.colorScheme.primary
                )
            ) {
                Text(
                    text = if (status.isRunning) "STOP" else "START",
                    fontSize = 18.sp
                )
            }

            if (status.isRunning) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Proxy running on port ${status.port}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = "Logs",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(4.dp))

            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                if (status.logs.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(8.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No logs yet. Start the proxy to see output.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    LazyColumn(
                        state = logListState,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(8.dp)
                    ) {
                        items(status.logs) { log ->
                            Text(
                                text = log,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                lineHeight = 16.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
