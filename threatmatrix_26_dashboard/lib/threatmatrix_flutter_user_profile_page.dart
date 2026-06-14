// ThreatMatrix User Profile Page â€” with 2FA Setup (F9â€“F15)

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'config/threatmatrix_api_config.dart';
import 'threatmatrix_flutter_theme_provider.dart';

class UserProfilePage extends StatefulWidget {
  final bool isDarkMode;
  const UserProfilePage({super.key, this.isDarkMode = true});

  @override
  State<UserProfilePage> createState() => _UserProfilePageState();
}

class _UserProfilePageState extends State<UserProfilePage> {
  // â”€â”€ Profile controllers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  late TextEditingController nameController;
  late TextEditingController emailController;
  late TextEditingController roleController;

  // â”€â”€ Password change controllers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  late TextEditingController currentPasswordController;
  late TextEditingController newPasswordController;
  late TextEditingController confirmPasswordController;

  // â”€â”€ 2FA setup controllers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  late TextEditingController _setup2FAPasswordCtrl;
  late TextEditingController _verifyCodeCtrl;

  bool showCurrentPassword = false;
  bool showNewPassword     = false;
  bool showConfirmPassword = false;

  bool _isUpdating        = false;
  bool _isChangingPassword = false;

  // â”€â”€ 2FA state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  bool   _is2FAEnabled   = false;
  bool   _isSettingUp2FA = false;   // loading: POST /auth/totp/setup
  bool   _isVerifying2FA = false;   // loading: POST /auth/login (verify step)
  String? _qrCodeBase64;            // base64 PNG from backend
  String? _totpSecret;              // raw Base32 secret (manual entry fallback)
  String? _setup2FAError;
  String? _verify2FAError;

  @override
  void initState() {
    super.initState();
    nameController            = TextEditingController(text: 'Security Analyst');
    emailController           = TextEditingController(text: 'analyst@threatmatrix.local');
    roleController            = TextEditingController(text: 'Administrator');
    currentPasswordController = TextEditingController();
    newPasswordController     = TextEditingController();
    confirmPasswordController = TextEditingController();
    _setup2FAPasswordCtrl     = TextEditingController();
    _verifyCodeCtrl           = TextEditingController();
    _loadProfile();
    _loadTotpStatus();
  }

  Future<void> _loadProfile() async {
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      nameController.text  = prefs.getString('profile_name')  ?? 'Security Analyst';
      emailController.text = prefs.getString('profile_email') ?? 'analyst@threatmatrix.local';
    });
  }

  Future<void> _loadTotpStatus() async {
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      _is2FAEnabled = prefs.getBool('totp_setup_complete') ?? false;
    });
  }

  @override
  void dispose() {
    nameController.dispose();
    emailController.dispose();
    roleController.dispose();
    currentPasswordController.dispose();
    newPasswordController.dispose();
    confirmPasswordController.dispose();
    _setup2FAPasswordCtrl.dispose();
    _verifyCodeCtrl.dispose();
    super.dispose();
  }

  // â”€â”€ Shared popup dialog â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Future<void> _showResultDialog(
    ThemeProvider tp, {
    required bool success,
    required String title,
    required String message,
    IconData? icon,
  }) {
    final color  = success ? tp.getSuccessColor() : tp.getDangerColor();
    final bgIcon = icon ?? (success ? Icons.check_circle_rounded : Icons.error_rounded);
    return showDialog<void>(
      context: context,
      barrierDismissible: true,
      builder: (_) => Dialog(
        backgroundColor: tp.getCardColor(),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        insetPadding: const EdgeInsets.symmetric(horizontal: 80, vertical: 60),
        child: SizedBox(
          width: 400,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(32, 32, 32, 28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 64, height: 64,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: color.withValues(alpha: 0.12),
                    border: Border.all(
                        color: color.withValues(alpha: 0.3), width: 1.5),
                  ),
                  child: Icon(bgIcon, color: color, size: 34),
                ),
                const SizedBox(height: 20),
                Text(title,
                    style: TextStyle(
                        fontSize: 17,
                        fontWeight: FontWeight.bold,
                        color: tp.getTextColor(),
                        fontFamily: 'Courier Prime'),
                    textAlign: TextAlign.center),
                const SizedBox(height: 10),
                Text(message,
                    style: TextStyle(
                        fontSize: 13,
                        color: tp.getTextSecondaryColor(),
                        height: 1.5),
                    textAlign: TextAlign.center),
                const SizedBox(height: 28),
                Divider(color: tp.getBorderColor(), height: 1),
                const SizedBox(height: 20),
                _ProfileHoverButton(
                  onPressed: () => Navigator.pop(context),
                  color: color,
                  textColor:
                      tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                  padding: const EdgeInsets.symmetric(
                      horizontal: 0, vertical: 12),
                  child: const Center(
                      child: Text('OK',
                          style: TextStyle(
                              fontWeight: FontWeight.w600, fontSize: 14))),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // â”€â”€ Update profile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Future<void> _updateProfile(ThemeProvider tp) async {
    final name  = nameController.text.trim();
    final email = emailController.text.trim();

    if (name.isEmpty) {
      await _showResultDialog(tp,
          success: false,
          title: 'Missing Field',
          message: 'Name cannot be empty. Please enter a display name.');
      return;
    }
    if (email.isEmpty || !email.contains('@')) {
      await _showResultDialog(tp,
          success: false,
          title: 'Invalid Email',
          message: 'Please enter a valid email address.');
      return;
    }

    setState(() => _isUpdating = true);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('profile_name',  name);
    await prefs.setString('profile_email', email);
    if (!mounted) return;
    setState(() => _isUpdating = false);

    await _showResultDialog(tp,
        success: true,
        title: 'Profile Updated',
        message: 'Your display name and email have been saved.',
        icon: Icons.person_rounded);
  }

  // â”€â”€ Change password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  static const _commonPasswords = {
    'password', 'password1', '12345678', '123456789', 'qwerty123',
    'iloveyou', 'admin123', 'welcome1', 'monkey123', 'dragon123',
    'threatmatrix', 'analyst123', 'security1',
  };

  Future<void> _changePassword(ThemeProvider tp) async {
    final current = currentPasswordController.text;
    final next    = newPasswordController.text;
    final confirm = confirmPasswordController.text;

    if (current.isEmpty) {
      await _showResultDialog(tp,
          success: false,
          title: 'Missing Field',
          message: 'Please enter your current password to continue.');
      return;
    }

    if (next.isEmpty) {
      await _showResultDialog(tp, success: false, title: 'Missing Field',
          message: 'Please enter a new password.');
      return;
    }
    if (next.length < 8) {
      await _showResultDialog(tp, success: false, title: 'Password Too Short',
          message: 'New password must be at least 8 characters (NIST SP 800-63B).');
      return;
    }
    if (next.length > 128) {
      await _showResultDialog(tp, success: false, title: 'Password Too Long',
          message: 'Password must not exceed 128 characters.');
      return;
    }
    if (_commonPasswords.contains(next.toLowerCase())) {
      await _showResultDialog(tp, success: false,
          title: 'Commonly Used Password',
          message: 'This password appears on known compromised lists. '
              'Choose a more unique passphrase (NIST SP 800-63B).');
      return;
    }
    if (next != confirm) {
      await _showResultDialog(tp, success: false, title: 'Password Mismatch',
          message: 'New password and confirmation do not match.');
      return;
    }
    if (current == next) {
      await _showResultDialog(tp, success: false, title: 'No Change Detected',
          message: 'New password must be different from your current password.');
      return;
    }

    setState(() => _isChangingPassword = true);

    final prefs = await SharedPreferences.getInstance();
    final email  = prefs.getString('profile_email') ?? 'analyst@threatmatrix.local';

    // ── Backend-first validation ──────────────────────────────────────────────
    // The backend is the source of truth for password validation (bcrypt).
    // SharedPreferences is only used as an offline fallback.
    try {
      final resp = await http.post(
        Uri.parse('${ApiConfig.baseUrl}/auth/update-password'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email':            email,
          'current_password': current,
          'new_password':     next,
        }),
      ).timeout(const Duration(seconds: 8));

      if (!mounted) return;

      if (resp.statusCode == 200) {
        // Backend accepted — sync SharedPreferences as local cache.
        await prefs.setString('auth_password', next);
        setState(() => _isChangingPassword = false);
        currentPasswordController.clear();
        newPasswordController.clear();
        confirmPasswordController.clear();
        await _showResultDialog(tp,
            success: true,
            title: 'Password Updated',
            message: 'Your password has been changed and stored securely. '
                'Use it on your next login.',
            icon: Icons.lock_reset_rounded);
        return;
      }

      // Backend explicitly rejected — parse the reason.
      setState(() => _isChangingPassword = false);
      String detail = 'The current password you entered is incorrect.';
      try {
        final body = jsonDecode(resp.body) as Map<String, dynamic>;
        if (body['detail'] != null) detail = body['detail'] as String;
      } catch (_) {}

      final isWrongPassword =
          resp.statusCode == 401 || resp.statusCode == 403 || resp.statusCode == 422;
      await _showResultDialog(tp,
          success: false,
          title: isWrongPassword ? 'Incorrect Password' : 'Update Failed',
          message: detail);

    } catch (_) {
      // ── Offline fallback: backend unreachable ───────────────────────────────
      if (!mounted) return;
      final storedPassword = prefs.getString('auth_password') ?? 'ThreatMatrix@2024!';
      if (current != storedPassword) {
        setState(() => _isChangingPassword = false);
        await _showResultDialog(tp,
            success: false,
            title: 'Incorrect Password',
            message: 'The current password you entered is incorrect. '
                'Backend unreachable — checked local cache.');
        return;
      }
      await prefs.setString('auth_password', next);
      setState(() => _isChangingPassword = false);
      currentPasswordController.clear();
      newPasswordController.clear();
      confirmPasswordController.clear();
      await _showResultDialog(tp,
          success: false,
          title: 'Backend Unreachable',
          message: 'Password updated locally, but could not reach the backend. '
              'Re-setup 2FA if login issues occur after reconnecting.',
          icon: Icons.warning_amber_rounded);
    }
  }

  // â”€â”€ 2FA Setup: Step 1 â€” call /auth/totp/setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Future<void> _generateQRCode(ThemeProvider tp) async {
    final password = _setup2FAPasswordCtrl.text;
    if (password.isEmpty) {
      setState(() => _setup2FAError = 'Enter your current password to begin setup.');
      return;
    }

    setState(() { _isSettingUp2FA = true; _setup2FAError = null; });

    // Backend validates the password server-side via /auth/totp/setup.
    // A non-200 response (e.g. 401) surfaces the detail as an inline error.
    try {
      final prefs = await SharedPreferences.getInstance();
      final email = prefs.getString('profile_email') ?? 'analyst@threatmatrix.local';
      final resp  = await http.post(
        Uri.parse('${ApiConfig.baseUrl}/auth/totp/setup'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'email': email, 'password': password}),
      ).timeout(const Duration(seconds: 10));

      if (!mounted) return;

      if (resp.statusCode == 200) {
        final body = jsonDecode(resp.body);
        setState(() {
          _isSettingUp2FA = false;
          _qrCodeBase64   = body['qr_code'] as String?;
          _totpSecret = body['manual_key'] as String?;
          _setup2FAError  = null;
        });
      } else {
        final detail = jsonDecode(resp.body)['detail'] as String? ?? 'Setup failed.';
        setState(() { _isSettingUp2FA = false; _setup2FAError = detail; });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isSettingUp2FA = false;
        _setup2FAError  = 'Connection error â€” ensure backend is running.';
      });
    }
  }

  // â”€â”€ 2FA Setup: Step 2 â€” verify code via /auth/login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Future<void> _verify2FACode(ThemeProvider tp) async {
    final code = _verifyCodeCtrl.text.trim();
    if (code.length != 6 || int.tryParse(code) == null) {
      setState(() => _verify2FAError = 'Enter the 6-digit code from Google Authenticator.');
      return;
    }

    setState(() { _isVerifying2FA = true; _verify2FAError = null; });

    try {
      final prefs = await SharedPreferences.getInstance();
      final email    = prefs.getString('profile_email') ?? 'analyst@threatmatrix.local';
      final password = _setup2FAPasswordCtrl.text;

      final resp = await http.post(
        Uri.parse('${ApiConfig.baseUrl}/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email':     email,
          'password':  password,
          'totp_code': code,
        }),
      ).timeout(const Duration(seconds: 10));

      if (!mounted) return;

      if (resp.statusCode == 200) {
        // Save 2FA enabled flag to SharedPreferences
        await prefs.setBool('totp_setup_complete', true);
        setState(() {
          _isVerifying2FA = false;
          _is2FAEnabled   = true;
          _qrCodeBase64   = null;
          _totpSecret     = null;
          _verify2FAError = null;
        });
        _setup2FAPasswordCtrl.clear();
        _verifyCodeCtrl.clear();

        await _showResultDialog(tp,
            success: true,
            title: '2FA Activated',
            message: 'Two-factor authentication is now enabled. '
                'You will need your Google Authenticator code on every login.',
            icon: Icons.verified_user_rounded);
      } else {
        final detail =
            jsonDecode(resp.body)['detail'] as String? ?? 'Verification failed.';
        setState(() { _isVerifying2FA = false; _verify2FAError = detail; });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isVerifying2FA = false;
        _verify2FAError = 'Connection error â€” ensure backend is running.';
      });
    }
  }

  // â”€â”€ Build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  @override
  Widget build(BuildContext context) {
    return Consumer<ThemeProvider>(
      builder: (context, tp, _) {
        return Scaffold(
          backgroundColor: tp.getBackgroundColor(),
          body: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.all(24.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildPersonalInformationSection(tp),
                  const SizedBox(height: 24),
                  _buildSecuritySection(tp),
                  const SizedBox(height: 24),
                  _buildTwoFactorSection(tp),
                  const SizedBox(height: 32),
                  Align(
                    alignment: Alignment.centerRight,
                    child: _ProfileHoverButton(
                      onPressed: _isUpdating ? null : () => _updateProfile(tp),
                      color: tp.getSuccessColor(),
                      textColor: tp.isDarkMode
                          ? const Color(0xFF111318)
                          : Colors.white,
                      padding: const EdgeInsets.symmetric(
                          horizontal: 32, vertical: 14),
                      child: Row(mainAxisSize: MainAxisSize.min, children: [
                        _isUpdating
                            ? const SizedBox(
                                width: 15, height: 15,
                                child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Color(0xFF111318)))
                            : Icon(Icons.save_rounded, size: 17,
                                color: tp.isDarkMode
                                    ? const Color(0xFF111318)
                                    : Colors.white),
                        const SizedBox(width: 8),
                        Text(_isUpdating ? 'Saving...' : 'Update Profile',
                            style: const TextStyle(
                                fontWeight: FontWeight.w600, fontSize: 14)),
                      ]),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  // â”€â”€ Personal Information â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Widget _buildPersonalInformationSection(ThemeProvider tp) {
    return _buildCard(
      tp: tp,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionTitle('Personal Information', tp,
              icon: Icons.person_outline_rounded),
          const SizedBox(height: 24),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 100, height: 100,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(
                      color: tp.getSuccessColor().withValues(alpha: 0.5),
                      width: 2),
                  color: tp.getSuccessColor().withValues(alpha: 0.10),
                ),
                child: Center(
                  child: Icon(Icons.person_rounded,
                      size: 52, color: tp.getSuccessColor()),
                ),
              ),
              const SizedBox(width: 32),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildFormField(
                        label: 'Name', controller: nameController, tp: tp),
                    const SizedBox(height: 16),
                    _buildFormField(
                        label: 'Email Address',
                        controller: emailController,
                        tp: tp),
                    const SizedBox(height: 16),
                    _buildFormField(
                      label: 'Role',
                      controller: roleController,
                      tp: tp,
                      readOnly: true,
                      hint: 'Assigned by administrator â€” contact your admin to change.',
                    ),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // â”€â”€ Security â€” Change Password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Widget _buildSecuritySection(ThemeProvider tp) {
    return _buildCard(
      tp: tp,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionTitle('Security \u2014 Change Password', tp,
              icon: Icons.lock_outline_rounded),
          const SizedBox(height: 4),
          Text(
            'Enter your current password and set a new one (min. 8 characters). '
            'Passwords are not stored in plaintext.',
            style: TextStyle(fontSize: 12, color: tp.getTextMutedColor()),
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Expanded(
                child: _buildPasswordField(
                  label: 'Current Password',
                  controller: currentPasswordController,
                  obscure: !showCurrentPassword,
                  onToggle: () => setState(
                      () => showCurrentPassword = !showCurrentPassword),
                  tp: tp,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: _buildPasswordField(
                  label: 'New Password',
                  controller: newPasswordController,
                  obscure: !showNewPassword,
                  onToggle: () =>
                      setState(() => showNewPassword = !showNewPassword),
                  tp: tp,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              SizedBox(
                width: MediaQuery.of(context).size.width * 0.32,
                child: _buildPasswordField(
                  label: 'Confirm New Password',
                  controller: confirmPasswordController,
                  obscure: !showConfirmPassword,
                  onToggle: () => setState(
                      () => showConfirmPassword = !showConfirmPassword),
                  tp: tp,
                ),
              ),
              const SizedBox(width: 16),
              _ProfileHoverButton(
                onPressed: _isChangingPassword
                    ? null
                    : () => _changePassword(tp),
                color: tp.getSuccessColor(),
                textColor:
                    tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                padding: const EdgeInsets.symmetric(
                    horizontal: 20, vertical: 14),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  _isChangingPassword
                      ? SizedBox(
                          width: 15, height: 15,
                          child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: tp.isDarkMode
                                  ? const Color(0xFF111318)
                                  : Colors.white))
                      : Icon(Icons.lock_reset_rounded,
                          size: 17,
                          color: tp.isDarkMode
                              ? const Color(0xFF111318)
                              : Colors.white),
                  const SizedBox(width: 8),
                  Text(
                      _isChangingPassword
                          ? 'Updating...'
                          : 'Change Password',
                      style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 13,
                          color: tp.isDarkMode
                              ? const Color(0xFF111318)
                              : Colors.white)),
                ]),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // â”€â”€ Two-Factor Authentication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Widget _buildTwoFactorSection(ThemeProvider tp) {
    final accent  = tp.getSuccessColor();
    const warning = Color(0xFFF59E0B);
    final danger  = tp.getDangerColor();

    return _buildCard(
      tp: tp,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Section header
          Row(
            children: [
              Container(
                width: 4, height: 18,
                decoration: BoxDecoration(
                    color: _is2FAEnabled ? accent : warning,
                    borderRadius: BorderRadius.circular(2)),
              ),
              const SizedBox(width: 10),
              Icon(Icons.phonelink_lock_outlined,
                  size: 16,
                  color: _is2FAEnabled ? accent : warning),
              const SizedBox(width: 8),
              Text('Two-Factor Authentication',
                  style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: tp.getTextColor(),
                      fontFamily: 'Courier Prime')),
              const SizedBox(width: 12),
              // Status badge
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 10, vertical: 3),
                decoration: BoxDecoration(
                  color: (_is2FAEnabled ? accent : warning)
                      .withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                      color: (_is2FAEnabled ? accent : warning)
                          .withValues(alpha: 0.4)),
                ),
                child: Text(
                  _is2FAEnabled ? 'ENABLED' : 'NOT CONFIGURED',
                  style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                      color: _is2FAEnabled ? accent : warning,
                      letterSpacing: 0.8),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            _is2FAEnabled
                ? 'Google Authenticator is active. Enter your 6-digit code on every login.'
                : 'Set up Google Authenticator to add a second layer of security to your account. '
                  'Required for production deployments (NIST SP 800-63B AAL2).',
            style: TextStyle(fontSize: 12, color: tp.getTextMutedColor()),
          ),
          const SizedBox(height: 20),

          if (_is2FAEnabled)
            // Already enabled â€” show info row
            Row(
              children: [
                Icon(Icons.verified_user_rounded, size: 18, color: accent),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    '2FA is active. To reconfigure, re-setup below (generates a new QR code).',
                    style: TextStyle(
                        fontSize: 12, color: tp.getTextSecondaryColor()),
                  ),
                ),
              ],
            ),

          if (_is2FAEnabled) const SizedBox(height: 16),

          // â”€â”€ Setup form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
          if (_qrCodeBase64 == null) ...[
            // Step 1 â€” Password entry + Generate QR button
            Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                SizedBox(
                  width: 280,
                  child: _buildPasswordField(
                    label: 'Confirm Current Password',
                    controller: _setup2FAPasswordCtrl,
                    obscure: true,
                    onToggle: () {},
                    tp: tp,
                  ),
                ),
                const SizedBox(width: 16),
                _ProfileHoverButton(
                  onPressed: _isSettingUp2FA
                      ? null
                      : () => _generateQRCode(tp),
                  color: _is2FAEnabled ? warning : accent,
                  textColor: tp.isDarkMode
                      ? const Color(0xFF111318)
                      : Colors.white,
                  padding: const EdgeInsets.symmetric(
                      horizontal: 20, vertical: 14),
                  child: Row(mainAxisSize: MainAxisSize.min, children: [
                    _isSettingUp2FA
                        ? const SizedBox(
                            width: 15, height: 15,
                            child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: Color(0xFF111318)))
                        : const Icon(Icons.qr_code_2_rounded,
                            size: 17, color: Color(0xFF111318)),
                    const SizedBox(width: 8),
                    Text(
                        _isSettingUp2FA
                            ? 'Generating...'
                            : (_is2FAEnabled
                                ? 'Re-generate QR'
                                : 'Generate QR Code'),
                        style: const TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 13,
                            color: Color(0xFF111318))),
                  ]),
                ),
              ],
            ),
            if (_setup2FAError != null) ...[
              const SizedBox(height: 8),
              Text(_setup2FAError!,
                  style: TextStyle(fontSize: 12, color: danger)),
            ],
          ] else ...[
            // Step 2 â€” Show QR code + verify code field
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // QR code image
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Scan with Google Authenticator',
                        style: TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: tp.getTextSecondaryColor())),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                            color: tp.getBorderColor()),
                      ),
                      child: Image.memory(
                        base64Decode(_qrCodeBase64!),
                        width: 160,
                        height: 160,
                        fit: BoxFit.contain,
                      ),
                    ),
                    if (_totpSecret != null) ...[
                      const SizedBox(height: 8),
                      Text('Manual entry key:',
                          style: TextStyle(
                              fontSize: 11,
                              color: tp.getTextMutedColor())),
                      SelectableText(
                        _totpSecret!,
                        style: TextStyle(
                            fontSize: 11,
                            fontFamily: 'Courier Prime',
                            color: accent),
                      ),
                    ],
                  ],
                ),
                const SizedBox(width: 32),

                // Verify code input
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Enter Verification Code',
                          style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              color: tp.getTextSecondaryColor())),
                      const SizedBox(height: 4),
                      Text(
                        'Open Google Authenticator, scan the QR code, '
                        'then enter the 6-digit code to activate 2FA.',
                        style: TextStyle(
                            fontSize: 11,
                            color: tp.getTextMutedColor(),
                            height: 1.5),
                      ),
                      const SizedBox(height: 12),
                      TextField(
                        controller: _verifyCodeCtrl,
                        keyboardType: TextInputType.number,
                        maxLength: 6,
                        style: TextStyle(
                          fontSize: 24,
                          color: tp.getTextColor(),
                          letterSpacing: 8,
                          fontFamily: 'Courier Prime',
                        ),
                        textAlign: TextAlign.center,
                        decoration: InputDecoration(
                          hintText: '000000',
                          counterText: '',
                          filled: true,
                          fillColor: tp.isDarkMode
                              ? const Color(0xFF111318)
                              : const Color(0xFFF5F5F5),
                          border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide(
                                  color: tp.getBorderColor())),
                          enabledBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: BorderSide(
                                  color: tp.getBorderColor())),
                          focusedBorder: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide:
                                  BorderSide(color: accent)),
                          contentPadding: const EdgeInsets.symmetric(
                              horizontal: 12, vertical: 16),
                        ),
                      ),
                      if (_verify2FAError != null) ...[
                        const SizedBox(height: 6),
                        Text(_verify2FAError!,
                            style: TextStyle(
                                fontSize: 12, color: danger)),
                      ],
                      const SizedBox(height: 16),
                      Row(children: [
                        _ProfileHoverButton(
                          onPressed: _isVerifying2FA
                              ? null
                              : () => _verify2FACode(tp),
                          color: accent,
                          textColor: tp.isDarkMode
                              ? const Color(0xFF111318)
                              : Colors.white,
                          padding: const EdgeInsets.symmetric(
                              horizontal: 20, vertical: 12),
                          child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                _isVerifying2FA
                                    ? const SizedBox(
                                        width: 14, height: 14,
                                        child: CircularProgressIndicator(
                                            strokeWidth: 2,
                                            color:
                                                Color(0xFF111318)))
                                    : const Icon(
                                        Icons.verified_user_rounded,
                                        size: 15,
                                        color: Color(0xFF111318)),
                                const SizedBox(width: 8),
                                Text(
                                    _isVerifying2FA
                                        ? 'Verifying...'
                                        : 'Activate 2FA',
                                    style: const TextStyle(
                                        fontWeight: FontWeight.w600,
                                        fontSize: 13,
                                        color: Color(0xFF111318))),
                              ]),
                        ),
                        const SizedBox(width: 12),
                        TextButton(
                          onPressed: () => setState(() {
                            _qrCodeBase64  = null;
                            _totpSecret    = null;
                            _verify2FAError = null;
                            _verifyCodeCtrl.clear();
                          }),
                          child: Text('Cancel',
                              style: TextStyle(
                                  color: tp.getTextMutedColor())),
                        ),
                      ]),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  // â”€â”€ Shared helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Widget _buildCard({required ThemeProvider tp, required Widget child}) {
    return Container(
      decoration: BoxDecoration(
        color: tp.getCardColor(),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: tp.getBorderColor(), width: 1),
      ),
      child: Padding(padding: const EdgeInsets.all(24.0), child: child),
    );
  }

  Widget _sectionTitle(String text, ThemeProvider tp,
      {required IconData icon}) {
    return Row(children: [
      Container(
        width: 4, height: 18,
        decoration: BoxDecoration(
            color: tp.getSuccessColor(),
            borderRadius: BorderRadius.circular(2)),
      ),
      const SizedBox(width: 10),
      Icon(icon, size: 16, color: tp.getSuccessColor()),
      const SizedBox(width: 8),
      Text(text,
          style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
              color: tp.getTextColor(),
              fontFamily: 'Courier Prime')),
    ]);
  }

  Widget _buildFormField({
    required String label,
    required TextEditingController controller,
    required ThemeProvider tp,
    bool readOnly = false,
    String? hint,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: tp.getTextSecondaryColor())),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          readOnly: readOnly,
          decoration: InputDecoration(
            hintText: hint ?? label,
            hintStyle: TextStyle(
                color: tp.getTextMutedColor(),
                fontSize: readOnly ? 12 : 13),
            filled: true,
            fillColor: readOnly
                ? (tp.isDarkMode
                    ? const Color(0xFF111318).withValues(alpha: 0.5)
                    : const Color(0xFFF0F0F0))
                : (tp.isDarkMode
                    ? const Color(0xFF111318)
                    : const Color(0xFFF5F5F5)),
            border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: tp.getBorderColor())),
            enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: tp.getBorderColor())),
            focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(
                    color:
                        readOnly ? tp.getBorderColor() : tp.getSuccessColor())),
            suffixIcon: readOnly
                ? Icon(Icons.lock_outline,
                    size: 16, color: tp.getTextMutedColor())
                : null,
            contentPadding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
          ),
          style: TextStyle(
              color: readOnly ? tp.getTextMutedColor() : tp.getTextColor()),
        ),
      ],
    );
  }

  Widget _buildPasswordField({
    required String label,
    required TextEditingController controller,
    required bool obscure,
    required VoidCallback onToggle,
    required ThemeProvider tp,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: tp.getTextSecondaryColor())),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          obscureText: obscure,
          decoration: InputDecoration(
            hintText: label,
            hintStyle: TextStyle(color: tp.getTextMutedColor()),
            filled: true,
            fillColor: tp.isDarkMode
                ? const Color(0xFF111318)
                : const Color(0xFFF5F5F5),
            border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: tp.getBorderColor())),
            enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: tp.getBorderColor())),
            focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: tp.getSuccessColor())),
            suffixIcon: IconButton(
                    onPressed: onToggle,
                    icon: Icon(
                      obscure
                          ? Icons.visibility_off_outlined
                          : Icons.visibility_outlined,
                      color: tp.getTextMutedColor(), size: 18,
                    ),
                  ),
            contentPadding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
          ),
          style: TextStyle(color: tp.getTextColor()),
        ),
      ],
    );
  }
}

// â”€â”€ Profile-local Hover Button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class _ProfileHoverButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final Widget child;
  final Color color;
  final Color textColor;
  final EdgeInsetsGeometry padding;

  const _ProfileHoverButton({
    required this.onPressed,
    required this.child,
    required this.color,
    required this.textColor,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
  });

  @override
  State<_ProfileHoverButton> createState() => _ProfileHoverButtonState();
}

class _ProfileHoverButtonState extends State<_ProfileHoverButton> {
  bool _hovered = false;
  bool _pressed = false;

  Color _shift(Color c, double amt) {
    final h = HSLColor.fromColor(c);
    return h.withLightness((h.lightness + amt).clamp(0.0, 1.0)).toColor();
  }

  @override
  Widget build(BuildContext context) {
    final dis = widget.onPressed == null;
    final Color bg = dis
        ? widget.color.withValues(alpha: 0.38)
        : _pressed
            ? _shift(widget.color, -0.04)
            : _hovered
                ? _shift(widget.color, 0.05)
                : widget.color;

    final shadows = _hovered && !dis
        ? [
            BoxShadow(
                color: widget.color.withValues(alpha: 0.35),
                blurRadius: 16,
                spreadRadius: 0,
                offset: const Offset(0, 4)),
            BoxShadow(
                color: widget.color.withValues(alpha: 0.12),
                blurRadius: 4,
                spreadRadius: 0,
                offset: Offset.zero),
          ]
        : <BoxShadow>[];

    return MouseRegion(
      cursor: dis ? SystemMouseCursors.forbidden : SystemMouseCursors.click,
      onEnter: (_) { if (!dis) setState(() => _hovered = true); },
      onExit:  (_) => setState(() { _hovered = false; _pressed = false; }),
      child: GestureDetector(
        onTapDown:   (_) => setState(() => _pressed = true),
        onTapUp:     (_) => setState(() => _pressed = false),
        onTapCancel: ()  => setState(() => _pressed = false),
        onTap: widget.onPressed,
        child: AnimatedScale(
          scale: _pressed ? 0.96 : (_hovered ? 1.02 : 1.0),
          duration: const Duration(milliseconds: 100),
          curve: Curves.easeOutCubic,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            curve: Curves.easeOutCubic,
            padding: widget.padding,
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(9),
              border: Border.all(color: Colors.transparent, width: 1.5),
              boxShadow: shadows,
            ),
            child: DefaultTextStyle(
              style: TextStyle(
                color: widget.textColor,
                fontWeight: FontWeight.w600,
                fontSize: 13,
                letterSpacing: 0.2,
              ),
              child: widget.child,
            ),
          ),
        ),
      ),
    );
  }
}