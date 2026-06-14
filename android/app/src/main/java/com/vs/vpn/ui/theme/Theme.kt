package com.vs.vpn.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = LightGreen,
    secondary = AccentGreen,
    tertiary = MediumGreen,
    background = SurfaceDark
)

private val LightColorScheme = lightColorScheme(
    primary = DarkGreen,
    secondary = MediumGreen,
    tertiary = LightGreen,
    background = SurfaceLight
)

@Composable
fun VsVpnTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = LightColorScheme,
        typography = Typography,
        content = content
    )
}
