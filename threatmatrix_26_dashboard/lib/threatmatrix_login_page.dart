// ThreatMatrix Login Page — with 2FA TOTP (F9–F15)
//
// Login flow:
//   Step 1 — Email + Password
//     If 2FA not set up: verify against SharedPreferences (legacy fallback).
//     If 2FA is set up:  validate format only, advance to Step 2.
//   Step 2 — 6-digit TOTP code
//     POST /auth/login {email, password, totp_code} → backend verifies all 3.
//
// 2FA status is stored in SharedPreferences key 'totp_setup_complete' (bool).
// Set to true by User Profile page after successful QR setup + verification.

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'config/threatmatrix_api_config.dart';
import 'main.dart'; // MainDashboard
import 'threatmatrix_flutter_theme_provider.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _emailCtrl    = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _totpCtrl     = TextEditingController();
  final _formKey      = GlobalKey<FormState>();

  bool _obscurePassword = true;
  bool _isLoading       = false;
  String? _errorMessage;
  int  _step            = 1;   // 1 = email+password, 2 = TOTP
  bool _totpEnabled     = false;

  // NIST SP 800-63B — account lockout after 4 consecutive failures
  int _failedAttempts = 0;
  static const int _maxAttempts = 4;
  bool get _isLocked => _failedAttempts >= _maxAttempts;

  static const String _defaultEmail    = 'analyst@threatmatrix.local';
  static const String _defaultPassword = 'ThreatMatrix@2024!';

  @override
  void initState() {
    super.initState();
    _loadTotpStatus();
  }

  Future<void> _loadTotpStatus() async {
    final prefs = await SharedPreferences.getInstance();
    if (mounted) {
      setState(() {
        _totpEnabled = prefs.getBool('totp_setup_complete') ?? false;
      });
    }
  }

  @override
  void dispose() {
    _emailCtrl.dispose();
    _passwordCtrl.dispose();
    _totpCtrl.dispose();
    super.dispose();
  }

  // ── Navigate to dashboard ──────────────────────────────────────────────────
  void _navigateToDashboard() {
    _failedAttempts = 0;
    setState(() => _isLoading = false);
    Navigator.of(context).pushReplacement(
      PageRouteBuilder(
        pageBuilder:      (_, __, ___) => const MainDashboard(),
        transitionsBuilder: (_, anim, __, child) =>
            FadeTransition(opacity: anim, child: child),
        transitionDuration: const Duration(milliseconds: 350),
      ),
    );
  }

  // ── Step 1: email + password ───────────────────────────────────────────────
  Future<void> _handleStep1() async {
    if (!(_formKey.currentState?.validate() ?? false)) return;
    if (_isLocked) {
      setState(() => _errorMessage =
          'Account locked after $_maxAttempts failed attempts. '
          'Restart the application to reset.');
      return;
    }

    setState(() { _isLoading = true; _errorMessage = null; });
    await Future.delayed(const Duration(milliseconds: 600));
    if (!mounted) return;

    if (_totpEnabled) {
      // 2FA configured — advance to TOTP step without checking credentials yet.
      // The backend verifies everything in Step 2.
      setState(() { _isLoading = false; _step = 2; });
      return;
    }

    // ── Legacy auth (no 2FA) via SharedPreferences ───────────────────────────
    final email    = _emailCtrl.text.trim();
    final password = _passwordCtrl.text;
    final prefs    = await SharedPreferences.getInstance();
    final storedEmail    = prefs.getString('profile_email') ?? _defaultEmail;
    final storedPassword = prefs.getString('auth_password') ?? _defaultPassword;

    if (!prefs.containsKey('auth_password')) {
      await prefs.setString('auth_password', _defaultPassword);
    }
    if (!prefs.containsKey('profile_email')) {
      await prefs.setString('profile_email', _defaultEmail);
    }

    if (email != storedEmail || password != storedPassword) {
      _failedAttempts++;
      final remaining = _maxAttempts - _failedAttempts;
      setState(() {
        _isLoading    = false;
        _errorMessage = _isLocked
            ? 'Account locked after $_maxAttempts failed attempts. '
              'Restart the application to reset.'
            : 'Invalid credentials. '
              '${remaining > 0 ? "$remaining attempt${remaining == 1 ? "" : "s"} remaining." : ""}';
      });
      return;
    }

    // Success — no 2FA required
    _navigateToDashboard();
  }

  // ── Step 2: TOTP verification via backend ──────────────────────────────────
  Future<void> _handleStep2() async {
    final code = _totpCtrl.text.trim();
    if (code.length != 6 || int.tryParse(code) == null) {
      setState(() => _errorMessage = 'Enter the 6-digit code from Google Authenticator.');
      return;
    }
    if (_isLocked) {
      setState(() => _errorMessage =
          'Account locked after $_maxAttempts failed attempts. '
          'Restart the application to reset.');
      return;
    }

    setState(() { _isLoading = true; _errorMessage = null; });

    try {
      final resp = await http.post(
        Uri.parse('${ApiConfig.baseUrl}/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email':     _emailCtrl.text.trim(),
          'password':  _passwordCtrl.text,
          'totp_code': code,
        }),
      ).timeout(const Duration(seconds: 10));

      if (!mounted) return;

      if (resp.statusCode == 200) {
        _navigateToDashboard();
      } else {
        _failedAttempts++;
        final body   = jsonDecode(resp.body);
        final detail = body['detail'] as String? ?? 'Authentication failed.';
        setState(() {
          _isLoading    = false;
          _errorMessage = _isLocked
              ? 'Account locked after $_maxAttempts failed attempts. '
                'Restart the application to reset.'
              : detail;
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isLoading    = false;
        _errorMessage = 'Connection error — ensure the backend is running '
            '(https://localhost/health).';
      });
    }
  }

  // ── Sign In dispatcher ─────────────────────────────────────────────────────
  Future<void> _signIn() async {
    if (_step == 1) {
      await _handleStep1();
    } else {
      await _handleStep2();
    }
  }

  // ── Build ──────────────────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    final tp        = context.watch<ThemeProvider>();
    final bg        = tp.getBackgroundColor();
    final card      = tp.getCardColor();
    final text      = tp.getTextColor();
    final muted     = tp.getTextMutedColor();
    final secondary = tp.getTextSecondaryColor();
    final border    = tp.getBorderColor();
    final accent    = tp.getSuccessColor();

    return Scaffold(
      backgroundColor: bg,
      body: LayoutBuilder(
        builder: (context, constraints) {
          return Stack(
            children: [
              // ── Full-screen scrollable background ─────────────────────────
              SingleChildScrollView(
                child: ConstrainedBox(
                  constraints: BoxConstraints(minHeight: constraints.maxHeight),
                  child: Container(
                    width: double.infinity,
                    color: bg,
                    child: Center(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 24, vertical: 48),
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 440),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              // ── Logo ────────────────────────────────────
                              Container(
                                width: 64, height: 64,
                                decoration: BoxDecoration(
                                  color: accent,
                                  borderRadius: BorderRadius.circular(16),
                                ),
                                child: Icon(Icons.security, color: bg, size: 34),
                              ),
                              const SizedBox(height: 14),
                              Text(
                                'ThreatMatrix',
                                style: TextStyle(
                                  fontSize: 26, fontWeight: FontWeight.bold,
                                  color: text, fontFamily: 'Courier Prime',
                                ),
                              ),
                              const SizedBox(height: 6),
                              Text(
                                'Network Threat Behavioural Analysis',
                                style: TextStyle(fontSize: 13, color: muted),
                                textAlign: TextAlign.center,
                              ),
                              const SizedBox(height: 28),

                              // ── Sign-In card ─────────────────────────────
                              Container(
                                decoration: BoxDecoration(
                                  color: card,
                                  borderRadius: BorderRadius.circular(14),
                                  border: Border.all(color: border),
                                  boxShadow: tp.isDarkMode
                                      ? null
                                      : [
                                          BoxShadow(
                                            color: Colors.black
                                                .withValues(alpha: 0.07),
                                            blurRadius: 20,
                                            offset: const Offset(0, 4),
                                          )
                                        ],
                                ),
                                padding: const EdgeInsets.fromLTRB(28, 24, 28, 28),
                                child: Form(
                                  key: _formKey,
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      // "Sign In" heading
                                      IntrinsicHeight(
                                        child: Row(
                                          children: [
                                            Container(
                                              width: 4,
                                              decoration: BoxDecoration(
                                                color: accent,
                                                borderRadius:
                                                    BorderRadius.circular(2),
                                              ),
                                            ),
                                            const SizedBox(width: 12),
                                            Text(
                                              _step == 1
                                                  ? 'Sign In'
                                                  : 'Two-Factor Authentication',
                                              style: TextStyle(
                                                fontSize: 20,
                                                fontWeight: FontWeight.bold,
                                                color: text,
                                                fontFamily: 'Courier Prime',
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),

                                      // Step 2 sub-heading
                                      if (_step == 2) ...[
                                        const SizedBox(height: 8),
                                        Text(
                                          'Enter the 6-digit code from Google Authenticator.',
                                          style: TextStyle(
                                              fontSize: 12, color: muted),
                                        ),
                                      ],
                                      const SizedBox(height: 24),

                                      // Error banner
                                      if (_errorMessage != null) ...[
                                        Container(
                                          padding: const EdgeInsets.symmetric(
                                              horizontal: 14, vertical: 10),
                                          margin: const EdgeInsets.only(
                                              bottom: 16),
                                          decoration: BoxDecoration(
                                            color: ThemeProvider.danger
                                                .withValues(alpha: 0.10),
                                            borderRadius:
                                                BorderRadius.circular(8),
                                            border: Border.all(
                                                color: ThemeProvider.danger
                                                    .withValues(alpha: 0.4)),
                                          ),
                                          child: Row(children: [
                                            const Icon(Icons.error_outline,
                                                size: 15,
                                                color: ThemeProvider.danger),
                                            const SizedBox(width: 8),
                                            Expanded(
                                              child: Text(_errorMessage!,
                                                  style: const TextStyle(
                                                      fontSize: 13,
                                                      color:
                                                          ThemeProvider.danger)),
                                            ),
                                          ]),
                                        ),
                                      ],

                                      // ── Step 1: Email + Password ─────────
                                      if (_step == 1) ...[
                                        Text('Email Address',
                                            style: TextStyle(
                                                fontSize: 13,
                                                fontWeight: FontWeight.w600,
                                                color: secondary)),
                                        const SizedBox(height: 6),
                                        TextFormField(
                                          controller: _emailCtrl,
                                          keyboardType:
                                              TextInputType.emailAddress,
                                          style: TextStyle(
                                              fontSize: 14, color: text),
                                          decoration: InputDecoration(
                                            hintText: 'you@example.com',
                                            prefixIcon: Icon(
                                                Icons.email_outlined,
                                                size: 18,
                                                color: muted),
                                          ),
                                          validator: (v) {
                                            if (v == null || v.trim().isEmpty) {
                                              return 'Email is required';
                                            }
                                            if (!v.contains('@')) {
                                              return 'Enter a valid email address';
                                            }
                                            return null;
                                          },
                                        ),
                                        const SizedBox(height: 16),
                                        Text('Password',
                                            style: TextStyle(
                                                fontSize: 13,
                                                fontWeight: FontWeight.w600,
                                                color: secondary)),
                                        const SizedBox(height: 6),
                                        TextFormField(
                                          controller: _passwordCtrl,
                                          obscureText: _obscurePassword,
                                          style: TextStyle(
                                              fontSize: 14, color: text),
                                          onFieldSubmitted: (_) => _signIn(),
                                          decoration: InputDecoration(
                                            hintText: '••••••••',
                                            prefixIcon: Icon(
                                                Icons.lock_outline,
                                                size: 18,
                                                color: muted),
                                            suffixIcon: IconButton(
                                              tooltip: _obscurePassword
                                                  ? 'Show password'
                                                  : 'Hide password',
                                              icon: Icon(
                                                _obscurePassword
                                                    ? Icons.visibility_outlined
                                                    : Icons
                                                        .visibility_off_outlined,
                                                size: 18,
                                                color: muted,
                                              ),
                                              onPressed: () => setState(() =>
                                                  _obscurePassword =
                                                      !_obscurePassword),
                                            ),
                                          ),
                                          validator: (v) {
                                            if (v == null || v.isEmpty) {
                                              return 'Password is required';
                                            }
                                            return null;
                                          },
                                        ),
                                      ],

                                      // ── Step 2: TOTP code field ───────────
                                      if (_step == 2) ...[
                                        Text('Authenticator Code',
                                            style: TextStyle(
                                                fontSize: 13,
                                                fontWeight: FontWeight.w600,
                                                color: secondary)),
                                        const SizedBox(height: 6),
                                        TextFormField(
                                          controller: _totpCtrl,
                                          keyboardType: TextInputType.number,
                                          maxLength: 6,
                                          style: TextStyle(
                                            fontSize: 22,
                                            color: text,
                                            letterSpacing: 8,
                                            fontFamily: 'Courier Prime',
                                          ),
                                          textAlign: TextAlign.center,
                                          onFieldSubmitted: (_) => _signIn(),
                                          decoration: InputDecoration(
                                            hintText: '000000',
                                            counterText: '',
                                            prefixIcon: Icon(
                                                Icons.phonelink_lock_outlined,
                                                size: 18,
                                                color: muted),
                                          ),
                                        ),
                                        const SizedBox(height: 8),
                                        // Back to step 1
                                        GestureDetector(
                                          onTap: () => setState(() {
                                            _step         = 1;
                                            _errorMessage = null;
                                            _totpCtrl.clear();
                                          }),
                                          child: Text(
                                            '← Back',
                                            style: TextStyle(
                                                fontSize: 12,
                                                color: accent,
                                                decoration:
                                                    TextDecoration.underline),
                                          ),
                                        ),
                                      ],

                                      const SizedBox(height: 22),

                                      // Sign In / Verify button
                                      SizedBox(
                                        width: double.infinity,
                                        height: 46,
                                        child: ElevatedButton(
                                          onPressed:
                                              _isLoading ? null : _signIn,
                                          style: ElevatedButton.styleFrom(
                                            backgroundColor: accent,
                                            foregroundColor: bg,
                                            disabledBackgroundColor:
                                                accent.withValues(alpha: 0.6),
                                            elevation: 0,
                                            shape: RoundedRectangleBorder(
                                              borderRadius:
                                                  BorderRadius.circular(8),
                                            ),
                                          ),
                                          child: _isLoading
                                              ? SizedBox(
                                                  width: 20, height: 20,
                                                  child:
                                                      CircularProgressIndicator(
                                                    strokeWidth: 2.5,
                                                    color: bg,
                                                  ),
                                                )
                                              : Text(
                                                  _step == 1
                                                      ? (_totpEnabled
                                                          ? 'Continue'
                                                          : 'Sign In')
                                                      : 'Verify',
                                                  style: TextStyle(
                                                    fontSize: 15,
                                                    fontWeight: FontWeight.bold,
                                                    color: bg,
                                                    fontFamily: 'Courier Prime',
                                                  ),
                                                ),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                              const SizedBox(height: 20),

                              const SizedBox(height: 12),
                              Text(
                                '© ${DateTime.now().year} ThreatMatrix. All rights reserved. '
                                '| MITRE ATT\u0026CK aligned',
                                style:
                                    TextStyle(fontSize: 11, color: muted),
                                textAlign: TextAlign.center,
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),

              // ── Theme toggle (floating top-right) ─────────────────────────
              Positioned(
                top: 16, right: 20,
                child: IconButton(
                  tooltip: tp.isDarkMode
                      ? 'Switch to light mode'
                      : 'Switch to dark mode',
                  onPressed: () =>
                      context.read<ThemeProvider>().toggleTheme(),
                  icon: Icon(
                    tp.isDarkMode
                        ? Icons.light_mode_outlined
                        : Icons.dark_mode_outlined,
                    color: accent,
                    size: 22,
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }
}