// ThreatMatrix Theme Provider
// Manages light and dark mode state across the application

import 'package:flutter/material.dart';

class ThemeProvider extends ChangeNotifier {
  bool _isDarkMode = false;

  bool get isDarkMode => _isDarkMode;

  void toggleTheme() {
    _isDarkMode = !_isDarkMode;
    notifyListeners();
  }

  void setDarkMode(bool isDark) {
    _isDarkMode = isDark;
    notifyListeners();
  }

  // ── Dark Mode Colors ─────────────────────────────────────────────────────────
  // Softened from pure near-black (0xFF0A0E14) to dark slate-gray to reduce
  // the neon-on-black effect that made accent colours look overly vivid.
  static const Color darkBackground = Color(0xFF111318);   // dark slate
  static const Color darkCard       = Color(0xFF1A1E28);   // slightly lighter
  static const Color darkBorder     = Color(0xFF252C3B);   // visible but subtle
  static const Color darkText            = Color(0xFFFFFFFF);
  static const Color darkTextSecondary   = Color(0xFF9CA3AF);
  static const Color darkTextMuted       = Color(0xFF6B7280);

  // ── Light Mode Colors ────────────────────────────────────────────────────────
  static const Color lightBackground    = Color(0xFFFAFAFA);
  static const Color lightCard          = Color(0xFFFFFFFF);
  static const Color lightBorder        = Color(0xFFE0E0E0);
  static const Color lightText          = Color(0xFF1A1A1A);
  static const Color lightTextSecondary = Color(0xFF424242);
  static const Color lightTextMuted     = Color(0xFF757575);

  // ── Semantic Colors ──────────────────────────────────────────────────────────
  // Dark-mode success uses a slightly muted green (0xFF00D966) instead of
  // the pure neon 0xFF00FF41, so it reads comfortably on the softer background.
  static const Color success      = Color(0xFF00D966);
  static const Color successLight = Color(0xFF4CAF50);
  static const Color danger       = Color(0xFFFF5252);
  static const Color dangerLight  = Color(0xFFE53935);
  static const Color warning      = Color(0xFFFFD600);
  static const Color warningLight = Color(0xFFFFA726);
  static const Color info         = Color(0xFF2196F3);

  Color getBackgroundColor()      => _isDarkMode ? darkBackground : lightBackground;
  Color getCardColor()            => _isDarkMode ? darkCard       : lightCard;
  Color getBorderColor()          => _isDarkMode ? darkBorder     : lightBorder;
  Color getTextColor()            => _isDarkMode ? darkText       : lightText;
  Color getTextSecondaryColor()   => _isDarkMode ? darkTextSecondary : lightTextSecondary;
  Color getTextMutedColor()       => _isDarkMode ? darkTextMuted  : lightTextMuted;
  Color getSuccessColor()         => _isDarkMode ? success        : successLight;
  Color getDangerColor()          => _isDarkMode ? danger         : dangerLight;
  Color getWarningColor()         => _isDarkMode ? warning        : warningLight;

  ThemeData getThemeData() {
    if (_isDarkMode) {
      return ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: darkBackground,
        primaryColor: success,
        fontFamily: 'Roboto',
        appBarTheme: const AppBarTheme(
          backgroundColor: darkBackground,
          foregroundColor: darkText,
          elevation: 0.0,
        ),
        cardTheme: CardThemeData(
          color: darkCard,
          elevation: 0.0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12.0),
            side: const BorderSide(color: darkBorder),
          ),
        ),
        inputDecorationTheme: const InputDecorationTheme(
          filled: true,
          fillColor: darkBackground,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: darkBorder),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: darkBorder),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: success),
          ),
          hintStyle: TextStyle(color: darkTextMuted),
          labelStyle: TextStyle(color: darkTextSecondary),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: success,
            foregroundColor: darkBackground,
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          ),
        ),
        textTheme: const TextTheme(
          displayLarge: TextStyle(
            fontSize: 32, fontWeight: FontWeight.bold,
            color: darkText, fontFamily: 'Courier Prime',
          ),
          headlineSmall: TextStyle(
            fontSize: 18, fontWeight: FontWeight.bold,
            color: darkText, fontFamily: 'Courier Prime',
          ),
          bodyLarge:  TextStyle(fontSize: 16, color: darkText),
          bodyMedium: TextStyle(fontSize: 14, color: darkTextSecondary),
          bodySmall:  TextStyle(fontSize: 12, color: darkTextMuted),
        ),
      );
    } else {
      return ThemeData(
        useMaterial3: true,
        brightness: Brightness.light,
        scaffoldBackgroundColor: lightBackground,
        primaryColor: successLight,
        fontFamily: 'Roboto',
        appBarTheme: const AppBarTheme(
          backgroundColor: lightBackground,
          foregroundColor: lightText,
          elevation: 0.0,
        ),
        cardTheme: const CardThemeData(
          color: lightCard,
          elevation: 0.0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.all(Radius.circular(12.0)),
            side: BorderSide(color: lightBorder),
          ),
        ),
        inputDecorationTheme: const InputDecorationTheme(
          filled: true,
          fillColor: Color(0xFFF5F5F5),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: lightBorder),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: lightBorder),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(8.0)),
            borderSide: BorderSide(color: successLight),
          ),
          hintStyle: TextStyle(color: lightTextMuted),
          labelStyle: TextStyle(color: lightTextSecondary),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: successLight,
            foregroundColor: Colors.white,
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          ),
        ),
        textTheme: const TextTheme(
          displayLarge: TextStyle(
            fontSize: 32, fontWeight: FontWeight.bold,
            color: lightText, fontFamily: 'Courier Prime',
          ),
          headlineSmall: TextStyle(
            fontSize: 18, fontWeight: FontWeight.bold,
            color: lightText, fontFamily: 'Courier Prime',
          ),
          bodyLarge:  TextStyle(fontSize: 16, color: lightText),
          bodyMedium: TextStyle(fontSize: 14, color: lightTextSecondary),
          bodySmall:  TextStyle(fontSize: 12, color: lightTextMuted),
        ),
      );
    }
  }
}