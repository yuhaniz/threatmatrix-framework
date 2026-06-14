// ThreatMatrix System Settings Page

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'threatmatrix_flutter_theme_provider.dart';
import 'threatmatrix_api_service.dart';

class SettingsPage extends StatefulWidget {
  final bool isDarkMode;
  final Function(bool) onThemeChanged;

  const SettingsPage({
    super.key,
    this.isDarkMode = false,
    required this.onThemeChanged,
  });

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  // ── Backend status — fetched from GET /health on page load ─────────────────
  HealthStatus? _healthStatus;
  bool _statusLoading = false;

  final ThreatMatrixApiService _api = ThreatMatrixApiService();

  @override
  void initState() {
    super.initState();
    _fetchHealth();
  }

  Future<void> _fetchHealth() async {
    setState(() => _statusLoading = true);
    final status = await _api.getHealth();
    if (mounted) {
      setState(() {
        _healthStatus = status;
        _statusLoading = false;
      });
    }
  }

  @override
  void dispose() {
    super.dispose();
  }

  // ── Shared: modern popup dialog ──────────────────────────────────────────────

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
                // Icon circle
                Container(
                  width: 64, height: 64,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: color.withValues(alpha: 0.12),
                    border: Border.all(color: color.withValues(alpha: 0.3), width: 1.5),
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
                    style: TextStyle(fontSize: 13, color: tp.getTextSecondaryColor(), height: 1.5),
                    textAlign: TextAlign.center),
                const SizedBox(height: 28),
                Divider(color: tp.getBorderColor(), height: 1),
                const SizedBox(height: 20),
                _SettingsHoverButton(
                  onPressed: () => Navigator.pop(context),
                  color: color,
                  textColor: tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 0, vertical: 12),
                  child: const Center(child: Text('OK',
                      style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14))),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ── Build ────────────────────────────────────────────────────────────────────

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
                  _buildAppearanceSection(tp),
                  const SizedBox(height: 24),
                  _buildBackendStatusSection(tp),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  // ─── Appearance ───────────────────────────────────────────────────────────────

  Widget _buildAppearanceSection(ThemeProvider tp) {
    return _buildCard(
      tp: tp,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionTitle('Appearance', tp, icon: Icons.palette_outlined),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Dark Mode',
                      style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                          color: tp.getTextSecondaryColor())),
                  const SizedBox(height: 4),
                  Text(
                    tp.isDarkMode
                        ? 'Currently using dark theme — softer slate-gray palette'
                        : 'Currently using light theme',
                    style: TextStyle(fontSize: 12, color: tp.getTextMutedColor()),
                  ),
                ],
              ),
              Switch(
                value: tp.isDarkMode,
                onChanged: (value) {
                  context.read<ThemeProvider>().setDarkMode(value);
                  widget.onThemeChanged(value);
                },
                activeThumbColor: tp.getSuccessColor(),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ─── Backend Status ───────────────────────────────────────────────────────────

  Widget _buildBackendStatusSection(ThemeProvider tp) {
    return _buildCard(
      tp: tp,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _sectionTitle('Backend Status', tp, icon: Icons.monitor_heart_outlined),
              _SettingsHoverButton(
                onPressed: _statusLoading ? null : _fetchHealth,
                color: tp.getSuccessColor(),
                textColor: tp.getSuccessColor(),
                outlined: true,
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  _statusLoading
                      ? SizedBox(width: 14, height: 14,
                          child: CircularProgressIndicator(strokeWidth: 2, color: tp.getSuccessColor()))
                      : Icon(Icons.refresh_rounded, size: 15, color: tp.getSuccessColor()),
                  const SizedBox(width: 5),
                  Text('Refresh', style: TextStyle(fontSize: 12, color: tp.getSuccessColor(),
                      fontWeight: FontWeight.w600)),
                ]),
              ),
            ],
          ),
          const SizedBox(height: 14),
          if (_statusLoading)
            Center(child: CircularProgressIndicator(color: tp.getSuccessColor()))
          else
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                _statusChip('Pipeline',          _healthStatus?.isOnline    ?? false, tp),
                _statusChip('PHASE 1 Binary',    _healthStatus?.phase1Ready ?? false, tp),
                _statusChip('PHASE 2 Severity',  _healthStatus?.phase2Ready ?? false, tp),
                _statusChip('PHASE 3 RF + OSR',    _healthStatus?.phase3Ready ?? false, tp),
              ],
            ),
        ],
      ),
    );
  }

  Widget _statusChip(String label, bool ready, ThemeProvider tp) {
    final color = ready ? tp.getSuccessColor() : tp.getDangerColor();
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(
          width: 6, height: 6,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 6),
        Text(label, style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w700)),
      ]),
    );
  }

  // ─── Shared Helpers ───────────────────────────────────────────────────────────

  Widget _buildCard({required ThemeProvider tp, required Widget child}) {
    return Container(
      decoration: BoxDecoration(
        color: tp.getCardColor(),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: tp.getBorderColor()),
      ),
      child: Padding(padding: const EdgeInsets.all(24), child: child),
    );
  }

  Widget _sectionTitle(String text, ThemeProvider tp, {required IconData icon}) {
    return Row(children: [
      Container(
        width: 4, height: 18,
        decoration: BoxDecoration(
            color: tp.getSuccessColor(), borderRadius: BorderRadius.circular(2)),
      ),
      const SizedBox(width: 10),
      Icon(icon, size: 16, color: tp.getSuccessColor()),
      const SizedBox(width: 8),
      Text(text,
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold,
              color: tp.getTextColor(), fontFamily: 'Courier Prime')),
    ]);
  }
}


// ── Settings-local Hover Button — scale + pressed + shadow bloom ──────────────

class _SettingsHoverButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final Widget child;
  final Color color;
  final Color textColor;
  final EdgeInsetsGeometry padding;
  final bool outlined;

  const _SettingsHoverButton({
    required this.onPressed,
    required this.child,
    required this.color,
    required this.textColor,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
    this.outlined = false,
  });

  @override
  State<_SettingsHoverButton> createState() => _SettingsHoverButtonState();
}

class _SettingsHoverButtonState extends State<_SettingsHoverButton> {
  bool _hovered  = false;
  bool _pressed  = false;

  Color _shift(Color c, double amt) {
    final h = HSLColor.fromColor(c);
    return h.withLightness((h.lightness + amt).clamp(0.0, 1.0)).toColor();
  }

  @override
  Widget build(BuildContext context) {
    final dis = widget.onPressed == null;
    final Color bg = widget.outlined
        ? (_hovered ? widget.color.withValues(alpha: 0.10) : Colors.transparent)
        : dis  ? widget.color.withValues(alpha: 0.38)
        : _pressed ? _shift(widget.color, -0.04)
        : _hovered ? _shift(widget.color, 0.05)
        : widget.color;

    // Two-layer glow: ambient bloom + directional lift
    final List<BoxShadow> shadows = !widget.outlined && _hovered && !dis
        ? [
            BoxShadow(
              color: widget.color.withValues(alpha: 0.35),
              blurRadius: 16,
              spreadRadius: 0,
              offset: const Offset(0, 4),
            ),
            BoxShadow(
              color: widget.color.withValues(alpha: 0.12),
              blurRadius: 4,
              spreadRadius: 0,
              offset: Offset.zero,
            ),
          ]
        : [];

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
              border: Border.all(
                color: widget.outlined
                    ? widget.color.withValues(alpha: _hovered ? 0.80 : 0.55)
                    : Colors.transparent,
                width: 1.5,
              ),
              boxShadow: shadows,
            ),
            child: DefaultTextStyle(
              style: TextStyle(
                color: widget.outlined ? widget.color : widget.textColor,
                fontWeight: FontWeight.w600, fontSize: 13,
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