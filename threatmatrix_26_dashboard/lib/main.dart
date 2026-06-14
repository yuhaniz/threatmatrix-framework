// ThreatMatrix Dashboard: MAIN PAGE

import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'threatmatrix_flutter_theme_provider.dart';
import 'threatmatrix_login_page.dart';
import 'threatmatrix_flutter_reports_page.dart';
import 'threatmatrix_flutter_settings_page.dart';
import 'threatmatrix_flutter_user_profile_page.dart';
import 'threatmatrix_mitre_attack_page.dart';
import 'threatmatrix_provider.dart';
import 'threatmatrix_api_service.dart';


const double _fsPageTitle   = 20;
const double _fsSectionHead = 16;
const double _fsBody        = 14;
const double _fsCaption     = 12;
const double _fsTable       = 13;
const double _fsTileLabel   = 11;
const double _fsTileValue   = 30;
const double _fsMetricValue = 24;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MultiProvider(providers: [
    ChangeNotifierProvider(create: (_) => ThemeProvider()),
    ChangeNotifierProvider(create: (_) => ThreatMatrixProvider()),
  ], child: const ThreatMatrixApp()));
}

class ThreatMatrixApp extends StatelessWidget {
  const ThreatMatrixApp({super.key});
  @override
  Widget build(BuildContext context) {
    return Consumer<ThemeProvider>(
      builder: (_, tp, __) => MaterialApp(
        title: 'ThreatMatrix',
        theme: tp.getThemeData(),
        home: const _AppInitialiser(),
        debugShowCheckedModeBanner: false,
      ),
    );
  }
}

class _AppInitialiser extends StatefulWidget {
  const _AppInitialiser();
  @override
  State<_AppInitialiser> createState() => _AppInitialiserState();
}

class _AppInitialiserState extends State<_AppInitialiser> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback(
        (_) => context.read<ThreatMatrixProvider>().initialise());
  }
  @override
  Widget build(BuildContext context) => const LoginPage();
}

// ─── Main Shell ───────────────────────────────────────────────────────────────

class MainDashboard extends StatefulWidget {
  const MainDashboard({super.key});
  @override
  State<MainDashboard> createState() => _MainDashboardState();
}

class _MainDashboardState extends State<MainDashboard> {
  int _selectedIndex = 0;

  static const _navItems = [
    (Icons.grid_view_rounded,        'Dashboard',    0),
    (Icons.shield_outlined,          'MITRE ATT\u0026CK', 1),
    (Icons.analytics_rounded,        'Reports',      2),
    (Icons.tune_rounded,             'Settings',     3),
    (Icons.manage_accounts_rounded,  'User Profile', 4),
  ];

  static const _pageTitles = [
    'Threat Analysis Dashboard',
    'Attack Technique Reference',
    'Reports',
    'System Settings',
    'User Profile',
  ];

  @override
  Widget build(BuildContext context) {
    final tp = context.watch<ThemeProvider>();

    return Scaffold(
      backgroundColor: tp.getBackgroundColor(),
      body: Column(children: [
        Expanded(
          child: Row(children: [
            _buildSidebar(tp),
            Expanded(child: Column(children: [
              _buildTopBar(tp),
              Expanded(child: _buildPage(tp)),
            ])),
          ]),
        ),
        _buildFooter(tp),
      ]),
    );
  }

  Widget _buildFooter(ThemeProvider tp) => Container(
    height: 36,
    decoration: BoxDecoration(
      color: tp.getBackgroundColor(),
      border: Border(top: BorderSide(color: tp.getBorderColor())),
    ),
    child: Center(
      child: Text(
        '© ${DateTime.now().year} ThreatMatrix. All rights reserved. | MITRE ATT&CK aligned',
        style: TextStyle(fontSize: _fsCaption, color: tp.getTextMutedColor()),
      ),
    ),
  );

  Widget _buildSidebar(ThemeProvider tp) {
    final provider = context.watch<ThreatMatrixProvider>();
    return Container(
      width: 220,
      decoration: BoxDecoration(
        color: tp.getBackgroundColor(),
        border: Border(right: BorderSide(color: tp.getBorderColor())),
      ),
      child: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
          child: Row(children: [
            Container(
              width: 36, height: 36,
              decoration: BoxDecoration(
                color: tp.getSuccessColor(),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(Icons.security, color: tp.getBackgroundColor(), size: 20),
            ),
            const SizedBox(width: 10),
            Text('ThreatMatrix',
                style: TextStyle(
                    fontSize: _fsSectionHead, fontWeight: FontWeight.bold,
                    color: tp.getTextColor(), fontFamily: 'Courier Prime')),
          ]),
        ),
        Divider(color: tp.getBorderColor(), height: 1),
        const SizedBox(height: 8),
        Expanded(child: Column(
          children: _navItems.map((item) {
            final sel = _selectedIndex == item.$3;
            return Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              child: Material(
                color: Colors.transparent,
                child: InkWell(
                  onTap: () => setState(() => _selectedIndex = item.$3),
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: sel
                          ? tp.getSuccessColor().withValues(alpha: 0.12)
                          : Colors.transparent,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Row(children: [
                      Icon(item.$1,
                          color: sel ? tp.getSuccessColor() : tp.getTextMutedColor(),
                          size: 18),
                      const SizedBox(width: 10),
                      Expanded(child: Text(item.$2,
                          style: TextStyle(
                              fontSize: _fsBody,
                              fontWeight: sel ? FontWeight.w600 : FontWeight.w500,
                              color: sel ? tp.getSuccessColor() : tp.getTextSecondaryColor()))),
                    ]),
                  ),
                ),
              ),
            );
          }).toList(),
        )),
        Divider(color: tp.getBorderColor(), height: 1),
        Padding(
          padding: const EdgeInsets.all(14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            _dot(provider.health.isOnline ? tp.getSuccessColor() : tp.getDangerColor(),
                 provider.health.isOnline ? 'ML Service Online' : 'ML Service Offline', tp),
            const SizedBox(height: 6),
            _dot(provider.wsConnected ? tp.getSuccessColor() : tp.getWarningColor(),
                 provider.wsConnected ? 'Live Feed Active' : 'Connecting...', tp),
          ]),
        ),
      ]),
    );
  }

  Widget _dot(Color c, String label, ThemeProvider tp) => Row(children: [
    Container(width: 7, height: 7, decoration: BoxDecoration(color: c, shape: BoxShape.circle)),
    const SizedBox(width: 8),
    Expanded(child: Text(label,
        style: TextStyle(fontSize: _fsCaption, color: tp.getTextMutedColor()),
        overflow: TextOverflow.ellipsis)),
  ]);

  Widget _buildTopBar(ThemeProvider tp) {
    final provider = context.watch<ThreatMatrixProvider>();
    final count = provider.notificationCount;
    return Container(
      height: 60,
      decoration: BoxDecoration(
        color: tp.getBackgroundColor(),
        border: Border(bottom: BorderSide(color: tp.getBorderColor())),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text(_pageTitles[_selectedIndex],
              style: TextStyle(
                  fontSize: _fsPageTitle, fontWeight: FontWeight.bold,
                  color: tp.getTextColor(), fontFamily: 'Courier Prime')),
          Row(children: [
            Stack(children: [
              IconButton(
                onPressed: () {
                  provider.clearNotifications();
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                    content: Text(count > 0 ? '$count alerts cleared' : 'No new notifications'),
                    duration: const Duration(seconds: 2),
                  ));
                },
                icon: Icon(Icons.notifications_outlined,
                    color: tp.getTextMutedColor(), size: 22),
              ),
              if (count > 0) Positioned(right: 6, top: 6,
                child: Container(
                  padding: const EdgeInsets.all(2),
                  decoration: BoxDecoration(color: tp.getDangerColor(), shape: BoxShape.circle),
                  constraints: const BoxConstraints(minWidth: 14, minHeight: 14),
                  child: Text(count > 99 ? '99+' : '$count',
                      style: const TextStyle(color: Colors.white, fontSize: 8,
                          fontWeight: FontWeight.bold),
                      textAlign: TextAlign.center),
                )),
            ]),
            IconButton(
              onPressed: () => context.read<ThemeProvider>().toggleTheme(),
              icon: Icon(
                tp.isDarkMode ? Icons.light_mode_outlined : Icons.dark_mode_outlined,
                color: tp.getSuccessColor(), size: 22,
              ),
            ),
            const SizedBox(width: 4),
            Container(
              width: 36, height: 36,
              decoration: BoxDecoration(
                  color: tp.getSuccessColor(), borderRadius: BorderRadius.circular(8)),
              child: Center(child: Text('SA',
                  style: TextStyle(color: tp.getBackgroundColor(),
                      fontWeight: FontWeight.bold, fontSize: _fsCaption))),
            ),
            const SizedBox(width: 4),
            IconButton(
              tooltip: 'Sign out',
              onPressed: () async {
                final confirmed = await _showConfirmDialog(
                  context: context,
                  tp: tp,
                  title: 'Sign Out',
                  message: 'Are you sure you want to sign out of ThreatMatrix?',
                  confirmLabel: 'Sign Out',
                  confirmColor: tp.getDangerColor(),
                  icon: Icons.logout_rounded,
                );
                if (!confirmed || !mounted) return;
                Navigator.of(context).pushReplacement(
                  PageRouteBuilder(
                    pageBuilder: (_, __, ___) => const LoginPage(),
                    transitionsBuilder: (_, anim, __, child) =>
                        FadeTransition(opacity: anim, child: child),
                    transitionDuration: const Duration(milliseconds: 350),
                  ),
                );
              },
              icon: Icon(Icons.logout_rounded,
                  color: tp.getTextMutedColor(), size: 22),
            ),
          ]),
        ]),
      ),
    );
  }

  Widget _buildPage(ThemeProvider tp) {
    return SelectionArea(child: switch (_selectedIndex) {
      0 => const DashboardPage(),
      1 => const MitreAttackPage(),
      2 => ReportsPage(isDarkMode: tp.isDarkMode),
      3 => SettingsPage(
          isDarkMode: tp.isDarkMode,
          onThemeChanged: (v) => context.read<ThemeProvider>().setDarkMode(v)),
      4 => UserProfilePage(isDarkMode: tp.isDarkMode),
      _ => const DashboardPage(),
    });
  }
}

// ─── Dashboard Page ───────────────────────────────────────────────────────────

class DashboardPage extends StatefulWidget {
  const DashboardPage({super.key});
  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

// SHAP explanation state per threat entry
enum _ExplainStatus { idle, loading, loaded, expired, error }

class _ExplainState {
  final _ExplainStatus status;
  final List<Map<String, dynamic>> features; // top 3 [{name, value, shap}]
  const _ExplainState(this.status, [this.features = const []]);
}

class _DashboardPageState extends State<DashboardPage> {
  bool _logExpanded  = true;
  bool _groupedView  = false;
  Map<String, bool>? _groupExpanded;
  String? _expandedId;

  final Map<String, String> _investigationStatus = {};
  final Map<String, _ExplainState> _explainState = {};

  static const List<String> _invStates = [
    'New', 'Investigating', 'Resolved', 'False Positive',
  ];

  ThemeProvider get tp => context.read<ThemeProvider>();

  Color get _blue => tp.isDarkMode ? const Color(0xFF2196F3) : const Color(0xFF1565C0);

  Color get _labelColor => tp.isDarkMode ? const Color(0xFFB8C0CC) : const Color(0xFF374151);
  Color get _mutedColor  => tp.isDarkMode ? const Color(0xFF6B7280) : const Color(0xFF6B7280);
  Color get _textColor   => tp.isDarkMode ? Colors.white            : const Color(0xFF111827);
  Color get _cardBg      => tp.isDarkMode ? const Color(0xFF1A1E28) : Colors.white;
  Color get _pageBg      => tp.isDarkMode ? const Color(0xFF111318) : const Color(0xFFE8EBF0);
  Color get _borderColor => tp.isDarkMode ? const Color(0xFF252C3B) : const Color(0xFFCFD8DC);

  List<BoxShadow>? get _shadow => tp.isDarkMode
      ? null
      : [BoxShadow(color: Colors.black.withValues(alpha: 0.08),
                   blurRadius: 8, offset: const Offset(0, 2))];

  BoxDecoration _card() => BoxDecoration(
    color: _cardBg,
    borderRadius: BorderRadius.circular(10),
    border: Border.all(color: _borderColor),
    boxShadow: _shadow,
  );

  Widget _accentCard({required Color accent, required Widget child}) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(10),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: _cardBg,
          border: Border.all(color: _borderColor),
          boxShadow: _shadow,
        ),
        child: Stack(
          children: [
            Positioned(
              left: 0, top: 0, bottom: 0,
              child: Container(width: 4, color: accent),
            ),
            Padding(
              padding: const EdgeInsets.only(left: 4),
              child: child,
            ),
          ],
        ),
      ),
    );
  }

  Color _sevColor(String s) => switch (s.toLowerCase()) {
    'critical' => tp.getDangerColor(),
    'high'     => tp.getWarningColor(),
    'medium'   => _blue,
    _          => tp.getSuccessColor(),
  };

  // Returns the colour that matches the Attack Type Breakdown panel per tier.
  // Reconnaissance=red, Credential Abuse=orange, Active Exploitation=blue,
  // Novel/Unknown=purple.
  Color _mitreColor(String? tid) {
    if (tid == null || tid.isEmpty) return _mutedColor;
    if (tid.startsWith('T1595')) return tp.getDangerColor();   // Reconnaissance
    if (tid.startsWith('T1110')) return tp.getWarningColor();  // Credential Abuse
    if (tid.startsWith('T1190')) return _blue;                 // Active Exploitation
    return const Color(0xFF9C27B0);                            // Novel / unknown
  }

  Color _statusColor(String s) => switch (s.toLowerCase()) {
    'new'             => tp.getDangerColor(),
    'investigating'   => tp.getWarningColor(),
    'resolved'        => tp.getSuccessColor(),
    'false positive'  => _blue,
    _                 => _mutedColor,
  };

  IconData _statusIcon(String s) => switch (s.toLowerCase()) {
    'new'            => Icons.fiber_new_outlined,
    'investigating'  => Icons.search_outlined,
    'resolved'       => Icons.check_circle_outline,
    'false positive' => Icons.do_not_disturb_alt_outlined,
    _                => Icons.help_outline,
  };

  String _statusFor(ThreatEntry entry) {
    return _investigationStatus[entry.id] ?? 'New';
  }

  void _setStatus(String id, String newStatus) {
    setState(() => _investigationStatus[id] = newStatus);
  }

  @override
  Widget build(BuildContext context) {
    context.watch<ThemeProvider>();
    final p = context.watch<ThreatMatrixProvider>();
    final s = p.stats;

    return ColoredBox(
      color: _pageBg,
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          _statTilesRow(p, s),
          const SizedBox(height: 16),
          _engineStrip(p),
          const SizedBox(height: 16),
          SizedBox(
            height: 400,
            child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(flex: 3, child: _liveMonitorCard(p)),
              const SizedBox(width: 16),
              Expanded(flex: 2, child: _attackBreakdownCard(s)),
            ],
          )),
          const SizedBox(height: 16),
          _modelPerformanceCard(p),
          const SizedBox(height: 16),
          _threatLogCard(p),
        ]),
      ),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 1 — STAT TILES
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _statTilesRow(ThreatMatrixProvider p, DashboardStats s) {
    final score = p.riskScore;
    final riskColor = score >= 75 ? tp.getDangerColor()
        : score >= 50 ? tp.getWarningColor()
        : score >= 25 ? _blue
        : tp.getSuccessColor();

    return SizedBox(
      height: 150,
      child: Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Expanded(child: _tile(
          label: 'SYSTEM STATUS',
          value: p.systemStatusLabel,
          sub: p.systemStatusSubtitle,
          valueColor: p.health.isOnline ? tp.getSuccessColor() : tp.getDangerColor(),
          icon: p.health.isOnline ? Icons.check_circle_outline : Icons.error_outline,
          accent: p.health.isOnline ? tp.getSuccessColor() : tp.getDangerColor(),
        )),
        const SizedBox(width: 12),
        Expanded(child: _tile(
          label: 'THREATS DETECTED',
          value: s.totalThreats.toString(),
          sub: '${s.criticalThreats} critical',
          valueColor: s.totalThreats > 0 ? tp.getDangerColor() : tp.getSuccessColor(),
          icon: Icons.warning_amber_outlined,
          accent: s.totalThreats > 0 ? tp.getDangerColor() : tp.getSuccessColor(),
        )),
        const SizedBox(width: 12),
        Expanded(child: _riskTile(p, riskColor, score)),
        const SizedBox(width: 12),
        Expanded(child: _tile(
          label: 'BENIGN FLOWS',
          value: s.benignFlows.toString(),
          sub: '${s.uncertainFlows} unclassified',
          valueColor: _blue,
          icon: Icons.shield_outlined,
          accent: _blue,
        )),
      ],
    ));
  }

  Widget _tile({
    required String label,
    required String value,
    required String sub,
    required Color valueColor,
    required IconData icon,
    required Color accent,
  }) {
    return _accentCard(
      accent: accent,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Expanded(child: Text(label,
                style: TextStyle(
                    fontSize: _fsTileLabel,
                    fontWeight: FontWeight.w800,
                    color: _labelColor,
                    letterSpacing: 0.8),
                overflow: TextOverflow.ellipsis)),
            const SizedBox(width: 8),
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: accent.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Icon(icon, color: accent, size: 16),
            ),
          ]),
          const SizedBox(height: 14),
          Text(value,
              style: TextStyle(
                  fontSize: _fsTileValue, fontWeight: FontWeight.bold,
                  color: valueColor, fontFamily: 'Courier Prime', height: 1.0)),
          const SizedBox(height: 6),
          Text(sub,
              style: TextStyle(fontSize: _fsCaption, color: _mutedColor),
              overflow: TextOverflow.ellipsis),
        ]),
      ),
    );
  }

  Widget _riskTile(ThreatMatrixProvider p, Color color, double score) {
    return _accentCard(
      accent: color,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Text('RISK SCORE',
                style: TextStyle(
                    fontSize: _fsTileLabel,
                    fontWeight: FontWeight.w800,
                    color: _labelColor,
                    letterSpacing: 0.8)),
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Icon(Icons.monitor_heart_outlined, color: color, size: 16),
            ),
          ]),
          const SizedBox(height: 14),
          Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
            Text(score.toStringAsFixed(0),
                style: TextStyle(
                    fontSize: _fsTileValue, fontWeight: FontWeight.bold,
                    color: color, fontFamily: 'Courier Prime', height: 1.0)),
            Padding(
              padding: const EdgeInsets.only(bottom: 3, left: 4),
              child: Text('/100',
                  style: TextStyle(fontSize: _fsBody, color: _mutedColor)),
            ),
          ]),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: LinearProgressIndicator(
              value: score / 100,
              minHeight: 5,
              backgroundColor: _borderColor,
              valueColor: AlwaysStoppedAnimation<Color>(color),
            ),
          ),
          const SizedBox(height: 6),
          Text(p.riskLabel,
              style: TextStyle(fontSize: _fsCaption, color: color, fontWeight: FontWeight.w700)),
        ]),
      ),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 2 — DETECTION ENGINE STRIP
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _engineStrip(ThreatMatrixProvider p) {
    final h = p.health;

    Widget phase(String code, String label, bool ready) {
      final c = ready ? tp.getSuccessColor() : _mutedColor;
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: c.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: c.withValues(alpha: 0.3)),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Container(width: 7, height: 7,
              decoration: BoxDecoration(color: c, shape: BoxShape.circle)),
          const SizedBox(width: 8),
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(code,
                style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800,
                    color: c, letterSpacing: 0.6, fontFamily: 'Courier Prime')),
            Text(label,
                style: TextStyle(fontSize: _fsCaption, color: c, fontWeight: FontWeight.w500)),
          ]),
        ]),
      );
    }

    Widget arrow() => Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8),
      child: Icon(Icons.arrow_forward, color: _mutedColor, size: 14),
    );

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      decoration: _card(),
      child: Row(children: [
        Icon(Icons.memory, color: tp.getSuccessColor(), size: 18),
        const SizedBox(width: 10),
        Text('Detection Engine',
            style: TextStyle(fontSize: _fsSectionHead, fontWeight: FontWeight.bold,
                color: _textColor, fontFamily: 'Courier Prime')),
        const SizedBox(width: 20),
        phase('PHASE 1', 'Binary Detection', h.phase1Ready),
        arrow(),
        phase('PHASE 2', 'Severity Classification', h.phase2Ready),
        arrow(),
        phase('PHASE 3', 'Fine-grained RF + OSR', h.phase1Ready && h.phase2Ready),
        const Spacer(),
        // ── Live agent stats from /health ─────────────────────────────────
        if (h.wsClients != null) ...[
          _agentStat(Icons.people_outline,
              '${h.wsClients} client${h.wsClients == 1 ? '' : 's'}'),
          const SizedBox(width: 14),
        ],
        if (h.flowBuffer != null) ...[
          _agentStat(Icons.inbox_outlined, '${h.flowBuffer} buffered'),
          const SizedBox(width: 14),
        ],
        _PulsingDot(color: h.isOnline ? tp.getSuccessColor() : tp.getDangerColor()),
        const SizedBox(width: 8),
        Text(h.isOnline ? 'Pipeline Ready' : 'Pipeline Offline',
            style: TextStyle(
                fontSize: _fsBody, fontWeight: FontWeight.w600,
                color: h.isOnline ? tp.getSuccessColor() : tp.getDangerColor())),
      ]),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 3-LEFT — LIVE NETWORK MONITOR
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _liveMonitorCard(ThreatMatrixProvider p) {
    final s = p.stats;
    final isLive = p.wsConnected;
    final liveColor = isLive ? tp.getSuccessColor() : tp.getWarningColor();

    return Container(
      decoration: _card(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 0),
            child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Live Network Monitor',
                    style: TextStyle(fontSize: _fsSectionHead, fontWeight: FontWeight.bold,
                        color: _textColor, fontFamily: 'Courier Prime')),
                const SizedBox(height: 3),
                Text('Network traffic · Phase 1 → 2 → 3',
                    style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
              ]),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: liveColor.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: liveColor.withValues(alpha: 0.4)),
                ),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  _PulsingDot(color: liveColor),
                  const SizedBox(width: 7),
                  Text(isLive ? 'LIVE' : 'CONNECTING',
                      style: TextStyle(fontSize: _fsCaption, fontWeight: FontWeight.w700,
                          color: liveColor, fontFamily: 'Courier Prime', letterSpacing: 1.0)),
                ]),
              ),
            ]),
          ),
          const SizedBox(height: 14),
          if (p.scanError != null)
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 10),
              child: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: tp.getDangerColor().withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: tp.getDangerColor().withValues(alpha: 0.4)),
                ),
                child: Row(children: [
                  Icon(Icons.error_outline, color: tp.getDangerColor(), size: 14),
                  const SizedBox(width: 8),
                  Expanded(child: Text(p.scanError!,
                      style: TextStyle(fontSize: _fsCaption, color: tp.getDangerColor()))),
                ]),
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 0),
            child: _timeSeriesGraph(p),
          ),
          const SizedBox(height: 14),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
            child: _flowSummaryStatic(s),
          ),
        ],
      ),
    );
  }

  Widget _flowSummaryStatic(DashboardStats s) {
    final total = s.totalThreats + s.benignFlows + s.uncertainFlows;
    final items = [
      ('Total Flows',  total,             _textColor),
      ('Threats',      s.totalThreats,    tp.getDangerColor()),
      ('Benign',       s.benignFlows,     tp.getSuccessColor()),
      ('Unclassified', s.uncertainFlows,  tp.getWarningColor()),
    ];
    return Row(children: items.map((it) => Expanded(
      child: Container(
        margin: const EdgeInsets.only(right: 10),
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 12),
        decoration: BoxDecoration(
          color: it.$3.withValues(alpha: 0.07),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: it.$3.withValues(alpha: 0.22)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(it.$2.toString(),
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold,
                  color: it.$3, fontFamily: 'Courier Prime')),
          Text(it.$1, style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
        ]),
      ),
    )).toList());
  }

  Widget _timeSeriesGraph(ThreatMatrixProvider p) {
    final bg = tp.isDarkMode ? const Color(0xFF111318) : const Color(0xFFF4F6F9);
    final bd = tp.isDarkMode ? _borderColor : const Color(0xFFDDDDDD);
    return Container(
      height: 160,
      decoration: BoxDecoration(
        color: bg, borderRadius: BorderRadius.circular(6),
        border: Border.all(color: bd),
      ),
      child: p.timeSeries.isEmpty
          ? Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
              Icon(Icons.show_chart,
                  color: tp.getSuccessColor().withValues(alpha: 0.4), size: 28),
              const SizedBox(height: 6),
              Text('Time-series graph — updates every 60s',
                  style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
            ]))
          : Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  _legend(tp.getDangerColor(), 'Threats'),
                  const SizedBox(width: 14),
                  _legend(tp.getSuccessColor(), 'Benign'),
                  const SizedBox(width: 14),
                  _legend(tp.getWarningColor(), 'Uncertain'),
                ]),
                const SizedBox(height: 6),
                Expanded(child: CustomPaint(
                  painter: _TimeSeriesPainter(
                    dataPoints: p.timeSeries,
                    threatColor: tp.getDangerColor(),
                    benignColor: tp.getSuccessColor(),
                    uncertainColor: tp.getWarningColor(),
                    gridColor: _borderColor,
                    isDark: tp.isDarkMode,
                  ),
                  child: const SizedBox.expand(),
                )),
              ]),
            ),
    );
  }

  Widget _legend(Color c, String label) => Row(children: [
    Container(width: 10, height: 3,
        decoration: BoxDecoration(color: c, borderRadius: BorderRadius.circular(2))),
    const SizedBox(width: 4),
    Text(label, style: TextStyle(fontSize: 11, color: _mutedColor)),
  ]);

  // Compact icon + label used in the engine strip for WS clients / buffer.
  Widget _agentStat(IconData icon, String label) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Icon(icon, size: 13, color: _mutedColor),
      const SizedBox(width: 4),
      Text(label, style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
    ],
  );

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 3-RIGHT — ATTACK BREAKDOWN
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _attackBreakdownCard(DashboardStats s) {
    // CORRECTED: Reconnaissance row now uses T1595.001 (Active Scanning:
    // Scanning IP Blocks) which is the canonical MITRE-blessed technique
    // under TA0043 (Reconnaissance). Previously this row paired T1046
    // (Network Service Discovery) with TA0043, but per
    // attack.mitre.org/techniques/T1046/ that technique sits under
    // TA0007 (Discovery), not TA0043 — a pairing MITRE itself does not
    // make. T1046 remains a documented secondary mapping in
    // threatmatrix_mitre_nist_mapping.py for the post-foothold scenario.
    // See module docstring §5 for the full rationale.
    final items = [
      ('Reconnaissance',      'T1595.001', 'TA0043 Reconnaissance',    s.reconCount,     tp.getDangerColor()),
      ('Credential Abuse',    'T1110',     'TA0006 Credential Access', s.credAbuseCount, tp.getWarningColor()),
      ('Active Exploitation', 'T1190',     'TA0001 Initial Access',    s.exploitCount,   _blue),
      ('Unknown / Novel',     'T0000',     'Phase 3 OSR',              s.novelCount,     const Color(0xFF9C27B0)),
    ];
    final maxVal = [s.reconCount, s.credAbuseCount, s.exploitCount, s.novelCount]
        .fold<int>(0, math.max).toDouble();

    return Container(
      decoration: _card(),
      padding: const EdgeInsets.all(20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text('Attack Type Breakdown',
            style: TextStyle(fontSize: _fsSectionHead, fontWeight: FontWeight.bold,
                color: _textColor, fontFamily: 'Courier Prime')),
        const SizedBox(height: 3),
        Text('MITRE ATT&CK · Phase 2 tiers · Phase 3 classification',
            style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
        const SizedBox(height: 16),
        ...items.map((it) {
          final frac = maxVal > 0 ? it.$4 / maxVal : 0.0;
          return Padding(
            padding: const EdgeInsets.only(bottom: 16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                Row(children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                    decoration: BoxDecoration(
                      color: it.$5.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(it.$2,
                        style: TextStyle(fontSize: 9, color: it.$5,
                            fontFamily: 'Courier Prime', fontWeight: FontWeight.w800)),
                  ),
                  const SizedBox(width: 8),
                  Text(it.$1,
                      style: TextStyle(fontSize: _fsBody, fontWeight: FontWeight.w600,
                          color: _textColor)),
                ]),
                Text(it.$4.toString(),
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold,
                        color: it.$5, fontFamily: 'Courier Prime')),
              ]),
              const SizedBox(height: 3),
              Text(it.$3, style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
              const SizedBox(height: 6),
              ClipRRect(
                borderRadius: BorderRadius.circular(2),
                child: LinearProgressIndicator(
                  value: frac, minHeight: 4,
                  backgroundColor: _borderColor,
                  valueColor: AlwaysStoppedAnimation<Color>(it.$5),
                ),
              ),
            ]),
          );
        }),
      ]),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 4 — MODEL PERFORMANCE (3-phase tabbed card)
  // Reads MultiPhaseMetrics from provider. Each tab shows the certified metrics
  // for that phase from /metrics. Phase 1 is selected by default.
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _modelPerformanceCard(ThreatMatrixProvider p) {
    final m = p.modelMetrics;

    return Container(
      decoration: _card(),
      padding: const EdgeInsets.all(20),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

        // ── Header ──────────────────────────────────────────────────────────
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Model Performance',
                style: TextStyle(
                    fontSize: _fsSectionHead,
                    fontWeight: FontWeight.bold,
                    color: _textColor,
                    fontFamily: 'Courier Prime')),
            const SizedBox(height: 3),
            Text(
                m.evaluatedOn.isNotEmpty
                    ? m.evaluatedOn
                    : 'Fetched from backend · GET /metrics',
                style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
          ]),
          _HoverButton(
            onPressed: m.isLoading ? null : () => p.fetchMetrics(),
            color: tp.getSuccessColor(),
            textColor: tp.getSuccessColor(),
            outlined: true,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              m.isLoading
                  ? SizedBox(width: 14, height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2, color: tp.getSuccessColor()))
                  : Icon(Icons.refresh_rounded, size: 15, color: tp.getSuccessColor()),
              const SizedBox(width: 5),
              Text('Refresh',
                  style: TextStyle(fontSize: 12, color: tp.getSuccessColor(),
                      fontWeight: FontWeight.w600)),
            ]),
          ),
        ]),

        // ── No-data warning ──────────────────────────────────────────────────
        if (!m.isLoading && m.phase1.accuracy == null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: tp.getWarningColor().withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: tp.getWarningColor().withValues(alpha: 0.3)),
            ),
            child: Row(children: [
              Icon(Icons.info_outline, color: tp.getWarningColor(), size: 14),
              const SizedBox(width: 8),
              Expanded(child: Text(
                'Metrics unavailable. Backend must expose GET /metrics '
                'returning { phase_1, phase_2, phase_3 } objects.',
                style: TextStyle(fontSize: _fsCaption, color: tp.getWarningColor()),
              )),
            ]),
          ),
        ],

        const SizedBox(height: 16),

        // ── Phase tabs — _PhaseMetricsTabs is a top-level class below ────────
        _PhaseMetricsTabs(
          phases: [
            _PhaseTab(
              code: 'PHASE 1',
              shortLabel: 'Binary',
              fullLabel: m.phase1.label,
              description: m.phase1.description,
              metrics: m.phase1,
              isLoading: m.isLoading,
              accent: tp.getSuccessColor(),
              tp: tp,
              mutedColor: _mutedColor,
              labelColor: _labelColor,
              borderColor: _borderColor,
            ),
            _PhaseTab(
              code: 'PHASE 2',
              shortLabel: 'Severity',
              fullLabel: m.phase2.label,
              description: m.phase2.description,
              metrics: m.phase2,
              isLoading: m.isLoading,
              accent: tp.getWarningColor(),
              tp: tp,
              mutedColor: _mutedColor,
              labelColor: _labelColor,
              borderColor: _borderColor,
            ),
            _PhaseTab(
              code: 'PHASE 3',
              shortLabel: 'RF + OSR',
              fullLabel: m.phase3.label,
              description: m.phase3.description,
              metrics: m.phase3,
              isLoading: m.isLoading,
              noteOverride: m.phase3.note,
              accent: _blue,
              tp: tp,
              mutedColor: _mutedColor,
              labelColor: _labelColor,
              borderColor: _borderColor,
            ),
          ],
        ),
      ]),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════════
  // ROW 5 — THREAT LOG
  // ══════════════════════════════════════════════════════════════════════════════

  Widget _threatLogCard(ThreatMatrixProvider p) {
    final log = p.threatLog;

    int countBy(String s) => log.where((e) => _statusFor(e) == s).length;
    final newCount = countBy('New');
    final invCount = countBy('Investigating');
    final resCount = countBy('Resolved');
    final fpCount  = countBy('False Positive');

    return Container(
      decoration: _card(),
      child: Column(children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
          decoration: BoxDecoration(
            color: tp.isDarkMode
                ? const Color(0xFF111318).withValues(alpha: 0.7)
                : const Color(0xFFF1F3F6),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(10)),
            border: Border(bottom: BorderSide(color: _borderColor)),
          ),
          child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Expanded(
              child: Wrap(
                crossAxisAlignment: WrapCrossAlignment.center,
                spacing: 10, runSpacing: 6,
                children: [
                  Text('Threat Log',
                      style: TextStyle(fontSize: _fsSectionHead, fontWeight: FontWeight.bold,
                          color: _textColor, fontFamily: 'Courier Prime')),
                  _summaryPill('New',            newCount, tp.getDangerColor()),
                  _summaryPill('Investigating',  invCount, tp.getWarningColor()),
                  _summaryPill('Resolved',       resCount, tp.getSuccessColor()),
                  _summaryPill('False Positive', fpCount,  _blue),
                ],
              ),
            ),
            Row(children: [
              // ── List / Group toggle ──────────────────────────────────────
              _viewToggleButton('List',  !_groupedView, () => setState(() => _groupedView = false)),
              const SizedBox(width: 4),
              _viewToggleButton('Group',  _groupedView, () => setState(() => _groupedView = true)),
              const SizedBox(width: 8),
              _ClearLogButton(
                  enabled: log.isNotEmpty,
                  dangerColor: tp.getDangerColor(),
                  mutedColor: _mutedColor,
                  onPressed: () async {
                    final ok = await _showConfirmDialog(
                      context: context,
                      tp: tp,
                      title: 'Clear Threat Log',
                      message: 'This will permanently remove all ${log.length} entries from the threat log. This action cannot be undone.',
                      confirmLabel: 'Clear All',
                    );
                    if (ok) {
                      p.clearThreatLog();
                      setState(_investigationStatus.clear);
                    }
                  },
                ),
              IconButton(
                onPressed: () => setState(() => _logExpanded = !_logExpanded),
                icon: Icon(_logExpanded ? Icons.expand_less : Icons.expand_more,
                    color: tp.getSuccessColor()),
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ]),
          ]),
        ),

        if (_logExpanded) ...[
          _tableHeader(),
          Divider(color: _borderColor, height: 1),
          if (log.isEmpty)
            Padding(
              padding: const EdgeInsets.all(28),
              child: Center(child: Text(
                'Monitoring active — threats will appear here automatically.',
                style: TextStyle(fontSize: _fsBody, color: _mutedColor),
              )),
            )
          else if (_groupedView)
            _groupedThreatLog(log)
          else
            ...log.asMap().entries.map((e) => _threatRow(e.value, e.key)),
        ],
      ]),
    );
  }

  Widget _summaryPill(String label, int count, Color c) {
    final isEmpty = count == 0;
    final pillColor = isEmpty ? _mutedColor : c;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: pillColor.withValues(alpha: isEmpty ? 0.06 : 0.12),
        borderRadius: BorderRadius.circular(10),
        border: isEmpty
            ? Border.all(color: pillColor.withValues(alpha: 0.2))
            : null,
      ),
      child: Text('$count $label',
          style: TextStyle(fontSize: _fsCaption,
              color: pillColor, fontWeight: isEmpty ? FontWeight.w500 : FontWeight.w700)),
    );
  }

  Widget _viewToggleButton(String label, bool active, VoidCallback onTap) {
    final c = active ? _blue : _mutedColor;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: active ? _blue.withValues(alpha: 0.12) : Colors.transparent,
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: active ? _blue.withValues(alpha: 0.4) : _borderColor),
        ),
        child: Text(label,
            style: TextStyle(fontSize: _fsCaption, color: c, fontWeight: FontWeight.w600)),
      ),
    );
  }

  // Grouped view — categories match the Attack Type Breakdown panel exactly.
  Widget _groupedThreatLog(List<ThreatEntry> log) {
    final categories = [
      (
        label:   'Reconnaissance',
        tid:     'T1595',
        color:   tp.getDangerColor(),
        entries: log.where((e) =>
            (e.killChainPhase ?? '').toLowerCase().contains('reconnaissance') ||
            (e.mitreInfo?.techniqueId ?? '').startsWith('T1595')).toList(),
      ),
      (
        label:   'Credential Abuse',
        tid:     'T1110',
        color:   tp.getWarningColor(),
        entries: log.where((e) =>
            (e.killChainPhase ?? '').toLowerCase().contains('credential') ||
            (e.mitreInfo?.techniqueId ?? '').startsWith('T1110')).toList(),
      ),
      (
        label:   'Active Exploitation',
        tid:     'T1190',
        color:   _blue,
        entries: log.where((e) =>
            (e.killChainPhase ?? '').toLowerCase().contains('initial access') ||
            (e.mitreInfo?.techniqueId ?? '').startsWith('T1190')).toList(),
      ),
      (
        label:   'Unknown / Novel',
        tid:     'OSR',
        color:   const Color(0xFF9C27B0),
        entries: log.where((e) => e.isNovel).toList(),
      ),
    ];

    // Track which category sections are expanded (default: all open).
    _groupExpanded ??= {for (final c in categories) c.label: true};

    return Column(
      children: categories.map((cat) {
        final expanded = _groupExpanded![cat.label] ?? true;
        final count    = cat.entries.length;
        return Column(children: [
          // ── Category section header ──────────────────────────────────────
          InkWell(
            onTap: () => setState(() =>
                _groupExpanded![cat.label] = !expanded),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
              color: cat.color.withValues(alpha: 0.06),
              child: Row(children: [
                Icon(expanded ? Icons.expand_less : Icons.expand_more,
                    size: 16, color: cat.color),
                const SizedBox(width: 8),
                Text(cat.label,
                    style: TextStyle(fontSize: _fsCaption,
                        color: cat.color, fontWeight: FontWeight.w700,
                        fontFamily: 'Courier Prime')),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                  decoration: BoxDecoration(
                    color: cat.color.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text('$count',
                      style: TextStyle(fontSize: _fsCaption,
                          color: cat.color, fontWeight: FontWeight.w700)),
                ),
                if (count == 0) ...[
                  const SizedBox(width: 8),
                  Text('No threats in this category',
                      style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
                ],
              ]),
            ),
          ),
          Divider(color: _borderColor, height: 1),
          // ── Category rows ────────────────────────────────────────────────
          if (expanded && count > 0)
            ...cat.entries.asMap().entries.map((e) => _threatRow(e.value, e.key)),
        ]);
      }).toList(),
    );
  }

  Widget _tableHeader() {
    // ── Column group definitions (flex values must match _threatRow) ──────────
    // Groups: EVENT | NETWORK | THREAT INTEL | ASSESSMENT | WORKFLOW
    return Column(children: [
      // ── Group header bar ────────────────────────────────────────────────────
      Container(
        color: tp.isDarkMode
            ? const Color(0xFF111318)
            : const Color(0xFFF0F2F5),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 6),
          child: Row(children: [
            _groupLabel('EVENT',    flex: 5), // ID(2) + Timestamp(3)
            _vDivider(),
            _groupLabel('NETWORK',     flex: 4), // Origin(2) + Dest(2)
            _vDivider(),
            _groupLabel('THREAT INTEL',flex: 4), // Kill Chain(2) + MITRE(2)
            _vDivider(),
            _groupLabel('ASSESSMENT',  flex: 4), // Severity(2) + Confidence(2)
            _vDivider(),
            _groupLabel('WORKFLOW',    flex: 3), // Status(3)
          ]),
        ),
      ),
      // ── Column label bar ────────────────────────────────────────────────────
      Container(
        color: tp.isDarkMode
            ? const Color(0xFF111318).withValues(alpha: 0.6)
            : const Color(0xFFF7F8FA),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
          child: Row(children: [
            Expanded(flex: 2, child: _colLabel('ID')),
            Expanded(flex: 3, child: _colLabel('Timestamp')),
            _vDivider(),
            Expanded(flex: 2, child: _colLabel('Origin IP')),
            Expanded(flex: 2, child: _colLabel('Dest IP')),
            _vDivider(),
            Expanded(flex: 2, child: _colLabel('Kill Chain')),
            Expanded(flex: 2, child: _colLabel('MITRE')),
            _vDivider(),
            Expanded(flex: 2, child: _colLabel('Severity')),
            Expanded(flex: 2, child: _colLabel('Confidence')),
            _vDivider(),
            Expanded(flex: 3, child: _colLabel('Status')),
          ]),
        ),
      ),
    ]);
  }

  Widget _groupLabel(String text, {required int flex}) => Expanded(
    flex: flex,
    child: Text(text,
        textAlign: TextAlign.center,
        style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w800,
            color: tp.getSuccessColor().withValues(alpha: 0.8),
            letterSpacing: 1.0)),
  );

  Widget _colLabel(String text) => Text(text,
    textAlign: TextAlign.left,
    style: TextStyle(
        fontSize: 12, fontWeight: FontWeight.w700,
        color: _mutedColor, letterSpacing: 0.4));

  Widget _vDivider() => Container(
    width: 1, height: 16,
    color: _borderColor,
    margin: const EdgeInsets.symmetric(horizontal: 6),
  );

  Widget _threatRow(ThreatEntry entry, int idx) {
    final expanded = _expandedId == entry.id;
    final rowBg = idx % 2 == 0
        ? Colors.transparent
        : (tp.isDarkMode
            ? Colors.white.withValues(alpha: 0.02)
            : Colors.black.withValues(alpha: 0.013));

    final currentStatus = _statusFor(entry);

    return Column(children: [
      InkWell(
        onTap: () => setState(() => _expandedId = expanded ? null : entry.id),
        child: Container(
          color: rowBg,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
            child: Row(children: [
              Expanded(flex: 2, child: Text(entry.id,
                  style: TextStyle(fontSize: _fsTable, color: tp.getSuccessColor(),
                      fontFamily: 'Courier Prime', fontWeight: FontWeight.w600))),
              Expanded(flex: 3, child: Text(entry.formattedTimestamp,
                  style: TextStyle(fontSize: _fsCaption, color: _mutedColor))),
              _vDivider(),
              Expanded(flex: 2, child: Text(entry.originIp ?? '—',
                  style: TextStyle(fontSize: _fsCaption, color: _textColor,
                      fontFamily: 'Courier Prime'),
                  overflow: TextOverflow.ellipsis)),
              Expanded(flex: 2, child: Text(entry.destinationIp ?? '—',
                  style: TextStyle(fontSize: _fsCaption, color: _mutedColor,
                      fontFamily: 'Courier Prime'),
                  overflow: TextOverflow.ellipsis)),
              _vDivider(),
              Expanded(flex: 2, child: Text(entry.killChainPhase ?? '—',
                  style: TextStyle(fontSize: _fsCaption, color: _mutedColor),
                  overflow: TextOverflow.ellipsis)),
              Expanded(flex: 2, child: entry.mitreInfo != null
                  ? Align(alignment: Alignment.centerLeft,
                      child: Tooltip(
                        message: '${entry.mitreInfo!.techniqueName}\n${entry.mitreInfo!.tactic}',
                        child: Builder(builder: (ctx) {
                          final tid = entry.mitreInfo!.techniqueId.split(' ').first;
                          final mc  = _mitreColor(tid);
                          return Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: mc.withValues(alpha: 0.13),
                              borderRadius: BorderRadius.circular(3),
                            ),
                            child: Text(tid,
                                style: TextStyle(fontSize: 10, color: mc,
                                    fontFamily: 'Courier Prime', fontWeight: FontWeight.w700)),
                          );
                        }),
                      ))
                  : Text('—', style: TextStyle(fontSize: _fsCaption, color: _mutedColor))),
              _vDivider(),
              Expanded(flex: 2, child: Align(alignment: Alignment.centerLeft,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(
                    color: _sevColor(entry.severity).withValues(alpha: 0.13),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(entry.severity,
                      style: TextStyle(fontSize: 10, color: _sevColor(entry.severity),
                          fontWeight: FontWeight.w700)),
                ))),
              Expanded(flex: 2, child: Text(
                entry.modelConfidence != null
                    ? '${(entry.modelConfidence! * 100).toStringAsFixed(1)}%'
                    : entry.attackProbability != null
                        ? '${(entry.attackProbability! * 100).toStringAsFixed(1)}%'
                        : '—',
                style: TextStyle(fontSize: _fsTable, color: _mutedColor,
                    fontFamily: 'Courier Prime'))),
              _vDivider(),
              Expanded(flex: 3, child: _statusMenu(entry.id, currentStatus)),
            ]),
          ),
        ),
      ),
      if (expanded) _detailPanel(entry),
      Divider(color: _borderColor, height: 1),
    ]);
  }

  Widget _statusMenu(String entryId, String currentStatus) {
    final color = _statusColor(currentStatus);
    return Align(
      alignment: Alignment.centerLeft,
      child: PopupMenuButton<String>(
        tooltip: 'Change investigation status',
        position: PopupMenuPosition.under,
        color: _cardBg,
        onSelected: (newStatus) => _setStatus(entryId, newStatus),
        itemBuilder: (context) => _invStates.map((state) {
          final isCurrent = state == currentStatus;
          final c = _statusColor(state);
          return PopupMenuItem<String>(
            value: state,
            child: Row(children: [
              Icon(_statusIcon(state), size: 14, color: c),
              const SizedBox(width: 8),
              Text(state, style: TextStyle(
                  fontSize: _fsCaption,
                  color: _textColor,
                  fontWeight: isCurrent ? FontWeight.w700 : FontWeight.w400)),
              if (isCurrent) ...[
                const SizedBox(width: 6),
                Icon(Icons.check, size: 12, color: tp.getSuccessColor()),
              ],
            ]),
          );
        }).toList(),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.13),
            borderRadius: BorderRadius.circular(3),
            border: Border.all(color: color.withValues(alpha: 0.3)),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(_statusIcon(currentStatus), size: 11, color: color),
            const SizedBox(width: 5),
            Flexible(
              child: Text(currentStatus,
                  style: TextStyle(fontSize: 10, color: color,
                      fontWeight: FontWeight.w700),
                  overflow: TextOverflow.ellipsis),
            ),
            const SizedBox(width: 3),
            Icon(Icons.arrow_drop_down, size: 14, color: color),
          ]),
        ),
      ),
    );
  }

  Widget _detailPanel(ThreatEntry entry) {
    final sevColor = _sevColor(entry.severity);

    // ── Derived values ────────────────────────────────────────────────────────
    final p1Str = entry.attackProbability != null
        ? '${(entry.attackProbability! * 100).toStringAsFixed(1)}%' : '—';
    final p3Str = entry.modelConfidence != null
        ? '${(entry.modelConfidence! * 100).toStringAsFixed(1)}%' : '—';
    final p1Val = entry.attackProbability ?? 0.0;
    final p3Val = entry.modelConfidence   ?? 0.0;

    final nistCategory = entry.type.toLowerCase().contains('scan') ||
            entry.type.toLowerCase().contains('recon')
        ? 'Network Intrusion / Probe'
        : entry.type.toLowerCase().contains('brute') ||
                entry.type.toLowerCase().contains('credential')
            ? 'Unauthorized Access Attempt'
            : entry.type.toLowerCase().contains('sql') ||
                    entry.type.toLowerCase().contains('exploit')
                ? 'Malicious Code / Exploit'
                : entry.type.toLowerCase().contains('xss')
                    ? 'Malicious Code (Client-Side)'
                    : 'Atypical / Anomalous Usage';

    final nistPhase = entry.severity == 'Critical' || entry.severity == 'High'
        ? 'Detection & Analysis → Containment'
        : 'Detection & Analysis';

    final containmentSteps = entry.type.toLowerCase().contains('scan')
        ? ['Block source IP at perimeter firewall',
           'Update IDS/IPS signatures for scan pattern',
           'Audit exposed services — close unnecessary ports',
           'Correlate with subsequent lateral movement']
        : entry.type.toLowerCase().contains('brute') ||
              entry.type.toLowerCase().contains('credential')
            ? ['Lock all targeted accounts immediately',
               'Enforce MFA on all privileged endpoints',
               'Rate-limit authentication endpoints',
               'Rotate credentials for affected accounts']
            : entry.type.toLowerCase().contains('sql') ||
                  entry.type.toLowerCase().contains('exploit')
                ? ['Apply WAF virtual patch to affected endpoint',
                   'Isolate host and capture forensic image',
                   'Audit application logs for successful exploitation',
                   'Engage development team for emergency patch']
                : ['Quarantine flow — capture full PCAP',
                   'Escalate to Tier 2 analyst for triage',
                   'Cross-reference against known IOC databases',
                   'Document for Phase 3 OSR retraining pipeline'];

    // ── Phase 2 tier label ────────────────────────────────────────────────────
    final p2Tier = entry.type.toLowerCase().contains('scan') ||
            entry.type.toLowerCase().contains('recon')
        ? 'Reconnaissance'
        : entry.type.toLowerCase().contains('brute') ||
                entry.type.toLowerCase().contains('credential')
            ? 'Credential Abuse'
            : entry.type.toLowerCase().contains('sql') ||
                    entry.type.toLowerCase().contains('exploit')
                ? 'Active Exploitation'
                : 'Uncertain';

    return Container(
      width: double.infinity,
      margin: const EdgeInsets.fromLTRB(16, 0, 16, 4),
      decoration: BoxDecoration(
        color: tp.isDarkMode ? const Color(0xFF0E1219) : const Color(0xFFF2F5F9),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _borderColor),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

        // ══════════════════════════════════════════════════════════════════════
        // SECTION 1 — EVENT HEADER  (severity accent + IDs + novel badge)
        // ══════════════════════════════════════════════════════════════════════
        Container(
          decoration: BoxDecoration(
            color: sevColor.withValues(alpha: 0.06),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
            border: Border(bottom: BorderSide(color: _borderColor)),
          ),
          child: IntrinsicHeight(
            child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              // Left severity stripe
              Container(
                width: 4,
                decoration: BoxDecoration(
                  color: sevColor,
                  borderRadius: const BorderRadius.only(topLeft: Radius.circular(8)),
                ),
              ),
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  child: Row(children: [
                    // Event ID + timestamp
                    Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text(entry.id,
                          style: TextStyle(fontSize: 14, fontWeight: FontWeight.w800,
                              color: tp.getSuccessColor(), fontFamily: 'Courier Prime')),
                      const SizedBox(height: 2),
                      Text(entry.formattedTimestamp,
                          style: TextStyle(fontSize: 11, color: _mutedColor,
                              fontFamily: 'Courier Prime')),
                    ]),
                    const SizedBox(width: 20),
                    // Severity badge
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: sevColor.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(5),
                        border: Border.all(color: sevColor.withValues(alpha: 0.4)),
                      ),
                      child: Row(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.shield_rounded, size: 11, color: sevColor),
                        const SizedBox(width: 4),
                        Text(entry.severity.toUpperCase(),
                            style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
                                color: sevColor, letterSpacing: 0.6)),
                      ]),
                    ),
                    const SizedBox(width: 8),
                    // Attack type chip
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: _mutedColor.withValues(alpha: 0.08),
                        borderRadius: BorderRadius.circular(5),
                        border: Border.all(color: _borderColor),
                      ),
                      child: Text(entry.type,
                          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
                              color: _labelColor, fontFamily: 'Courier Prime')),
                    ),
                    const Spacer(),
                    // Novel badge
                    if (entry.isNovel)
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: tp.getWarningColor().withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(5),
                          border: Border.all(color: tp.getWarningColor().withValues(alpha: 0.45)),
                        ),
                        child: Row(mainAxisSize: MainAxisSize.min, children: [
                          Icon(Icons.new_releases_rounded, size: 11, color: tp.getWarningColor()),
                          const SizedBox(width: 4),
                          Text('NOVEL — unseen during training',
                              style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                                  color: tp.getWarningColor())),
                        ]),
                      ),
                    // Framework badges
                    const SizedBox(width: 12),
                    _frameworkBadge('MITRE ATT\u0026CK', const Color(0xFF1565C0)),
                    const SizedBox(width: 5),
                    _frameworkBadge('NIST SP 800-61r2', const Color(0xFF2E7D32)),
                  ]),
                ),
              ),
            ]),
          ),
        ),

        // ══════════════════════════════════════════════════════════════════════
        // SECTION 2 — ML DETECTION PIPELINE  (Phase 1 → Phase 2 → Phase 3)
        // ══════════════════════════════════════════════════════════════════════
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 14, 20, 0),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            _detailSectionLabel('ML DETECTION PIPELINE', Icons.account_tree_rounded,
                const Color(0xFF1565C0)),
            const SizedBox(height: 8),
            Row(children: [
              // Phase 1
              Expanded(child: _pipelinePhaseBox(
                phase: 'PHASE 1',
                label: 'Binary Detection',
                result: entry.attackProbability != null ? 'ATTACK' : '—',
                confidence: p1Str,
                confValue: p1Val,
                color: tp.getDangerColor(),
                icon: Icons.radar_rounded,
              )),
              _pipelineArrow(),
              // Phase 2
              Expanded(child: _pipelinePhaseBox(
                phase: 'PHASE 2',
                label: 'Severity Classification',
                result: p2Tier,
                confidence: null,
                confValue: null,
                color: tp.getWarningColor(),
                icon: Icons.sort_rounded,
              )),
              _pipelineArrow(),
              // Phase 3
              Expanded(child: _pipelinePhaseBox(
                phase: 'PHASE 3',
                label: 'Fine-grained RF + OSR',
                result: entry.isNovel ? 'UNKNOWN (Novel)' : entry.type,
                confidence: p3Str,
                confValue: p3Val,
                color: entry.isNovel ? tp.getWarningColor() : tp.getSuccessColor(),
                icon: Icons.manage_search_rounded,
              )),
            ]),
          ]),
        ),

        const SizedBox(height: 14),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20),
          child: Divider(color: _borderColor, height: 1),
        ),
        const SizedBox(height: 14),

        // ══════════════════════════════════════════════════════════════════════
        // SECTION 3 — THREE COLUMNS: MITRE | NETWORK | NIST
        // ══════════════════════════════════════════════════════════════════════
        Padding(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 0),
          child: IntrinsicHeight(
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [

              // ── Column A: MITRE ATT&CK ──────────────────────────────────────
              Expanded(child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _detailSectionLabel('MITRE ATT\u0026CK', Icons.security_rounded,
                      const Color(0xFF1565C0)),
                  const SizedBox(height: 10),
                  if (entry.mitreInfo != null) ...[
                    // Technique ID — large badge
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1565C0).withValues(alpha: 0.10),
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: const Color(0xFF1565C0).withValues(alpha: 0.35)),
                      ),
                      child: Row(mainAxisSize: MainAxisSize.min, children: [
                        Text(entry.mitreInfo!.techniqueId.split(' ').first,
                            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800,
                                color: Color(0xFF1565C0), fontFamily: 'Courier Prime')),
                      ]),
                    ),
                    const SizedBox(height: 8),
                    _detailRow('Technique',     entry.mitreInfo!.techniqueName, mono: false),
                    _detailRow('ATT\u0026CK Tactic', entry.mitreInfo!.tactic,       mono: false),
                    _detailRow('Kill Chain',    entry.killChainPhase ?? 'Unknown', mono: false),
                  ] else
                    _detailRow('Status', 'No mapping — novel attack vector', mono: false),
                ],
              )),

              _panelDivider(),

              // ── Column B: Network Telemetry ─────────────────────────────────
              Expanded(child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _detailSectionLabel('NETWORK TELEMETRY', Icons.hub_rounded,
                      const Color(0xFF6A1B9A)),
                  const SizedBox(height: 10),
                  // Source → Destination flow
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF6A1B9A).withValues(alpha: 0.06),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF6A1B9A).withValues(alpha: 0.2)),
                    ),
                    child: Row(children: [
                      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text('SOURCE', style: TextStyle(fontSize: 9,
                            fontWeight: FontWeight.w800, color: _mutedColor, letterSpacing: 0.6)),
                        const SizedBox(height: 3),
                        Text(entry.originIp ?? 'N/A',
                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700,
                                color: _textColor, fontFamily: 'Courier Prime')),
                      ])),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 8),
                        child: Icon(Icons.arrow_forward_rounded,
                            size: 14, color: _mutedColor),
                      ),
                      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text('DESTINATION', style: TextStyle(fontSize: 9,
                            fontWeight: FontWeight.w800, color: _mutedColor, letterSpacing: 0.6)),
                        const SizedBox(height: 3),
                        Text(entry.destinationIp ?? 'N/A',
                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700,
                                color: _textColor, fontFamily: 'Courier Prime')),
                      ])),
                    ]),
                  ),
                  const SizedBox(height: 8),
                  _detailRow('Attack Class', entry.type,              mono: true),
                  _detailRow('Ph.1 Attack Prob', p1Str,              mono: true),
                  _detailRow('Ph.3 Confidence',  p3Str,              mono: true),
                  _detailRow('IR Status',    _statusFor(entry),       mono: false),
                ],
              )),

              _panelDivider(),

              // ── Column C: NIST SP 800-61 Incident Response ──────────────────
              Expanded(child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _detailSectionLabel('NIST SP 800-61 RESPONSE', Icons.policy_rounded,
                      const Color(0xFF2E7D32)),
                  const SizedBox(height: 10),
                  _detailRow('IR Category', nistCategory, mono: false),
                  _detailRow('IR Phase',    nistPhase,    mono: false),
                  _detailRow('Severity',    entry.severity, mono: false),
                  const SizedBox(height: 8),
                  Text('CONTAINMENT ACTIONS',
                      style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800,
                          color: _mutedColor, letterSpacing: 0.6)),
                  const SizedBox(height: 5),
                  ...containmentSteps.asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Container(
                        width: 16, height: 16,
                        margin: const EdgeInsets.only(top: 1, right: 6),
                        decoration: BoxDecoration(
                          color: const Color(0xFF2E7D32).withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(3),
                        ),
                        child: Center(child: Text('${e.key + 1}',
                            style: const TextStyle(fontSize: 9,
                                fontWeight: FontWeight.w800, color: Color(0xFF2E7D32)))),
                      ),
                      Expanded(child: Text(e.value,
                          style: TextStyle(fontSize: 11, color: _labelColor, height: 1.4))),
                    ]),
                  )),
                ],
              )),
            ]),
          ),
        ),
        // ══════════════════════════════════════════════════════════════════════
        // SECTION 4 — BEHAVIOURAL EXPLANATION  (on-demand SHAP, Phase 3 only)
        // ══════════════════════════════════════════════════════════════════════
        if (entry.flowId != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 0, 20, 0),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Divider(color: _borderColor, height: 1),
              const SizedBox(height: 14),
              _detailSectionLabel(
                'BEHAVIOURAL EXPLANATION',
                Icons.biotech_rounded,
                const Color(0xFF00695C),
              ),
              const SizedBox(height: 10),
              _shapExplainWidget(entry),
              const SizedBox(height: 14),
            ]),
          ),

        const SizedBox(height: 16),
      ]),
    );
  }

  // ── SHAP feature display name map ─────────────────────────────────────────
  static const Map<String, String> _featureLabels = {
    'flow_duration':            'Flow duration',
    'fwd_pkts_tot':             'Forward packets (total)',
    'bwd_pkts_tot':             'Backward packets (total)',
    'fwd_data_pkts_tot':        'Forward data packets',
    'bwd_data_pkts_tot':        'Backward data packets',
    'flow_pkts_per_sec':        'Packet rate',
    'fwd_pkts_per_sec':         'Forward packet rate',
    'bwd_pkts_per_sec':         'Backward packet rate',
    'payload_bytes_per_second': 'Payload throughput',
    'down_up_ratio':            'Download / upload ratio',
    'fwd_header_size_tot':      'Forward header size',
    'bwd_header_size_tot':      'Backward header size',
    'flow_FIN_flag_count':      'FIN flag count',
    'flow_SYN_flag_count':      'SYN flag count',
    'flow_RST_flag_count':      'RST flag count',
    'flow_ACK_flag_count':      'ACK flag count',
  };

  // ── SHAP explain widget ────────────────────────────────────────────────────
  Widget _shapExplainWidget(ThreatEntry entry) {
    final state = _explainState[entry.id] ?? const _ExplainState(_ExplainStatus.idle);
    const teal  = Color(0xFF00695C);

    switch (state.status) {
      case _ExplainStatus.idle:
        return InkWell(
          onTap: () => _fetchExplain(entry),
          borderRadius: BorderRadius.circular(6),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: teal.withValues(alpha: 0.06),
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: teal.withValues(alpha: 0.25)),
            ),
            child: const Row(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.biotech_rounded, size: 13, color: teal),
              SizedBox(width: 6),
              Text('Explain behavioural signals',
                  style: TextStyle(fontSize: _fsCaption, color: teal,
                      fontWeight: FontWeight.w600)),
            ]),
          ),
        );

      case _ExplainStatus.loading:
        return Row(children: [
          SizedBox(
            width: 160,
            child: LinearProgressIndicator(
              color: teal,
              backgroundColor: teal.withValues(alpha: 0.12),
              minHeight: 2,
            ),
          ),
          const SizedBox(width: 10),
          Text('Fetching explanation…',
              style: TextStyle(fontSize: _fsCaption, color: _mutedColor)),
        ]);

      case _ExplainStatus.expired:
        return Text(
          'Explanation window has closed — the flow is no longer in the detection buffer.',
          style: TextStyle(fontSize: _fsCaption, color: _mutedColor),
        );

      case _ExplainStatus.error:
        return Text('Explanation unavailable.',
            style: TextStyle(fontSize: _fsCaption, color: _mutedColor));

      case _ExplainStatus.loaded:
        if (state.features.isEmpty) {
          return Text('No features returned.',
              style: TextStyle(fontSize: _fsCaption, color: _mutedColor));
        }
        final maxAbs = state.features
            .map((f) => (f['shap'] as double).abs())
            .reduce((a, b) => a > b ? a : b);
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Top behavioural features that contributed to this classification',
                style: TextStyle(fontSize: 10, color: _mutedColor,
                    fontWeight: FontWeight.w600, letterSpacing: 0.3)),
            const SizedBox(height: 4),
            Text('Pushed toward = feature made the model more confident in this class.  '
                 'Pushed against = feature reduced confidence.',
                style: TextStyle(fontSize: 10, color: _mutedColor, height: 1.4)),
            const SizedBox(height: 8),
            ...state.features.map((f) {
              final shap      = f['shap'] as double;
              final rawName   = f['feature'] as String;
              final label     = _featureLabels[rawName] ?? rawName;
              final value     = f['value'] as double;
              final isPos     = shap >= 0;
              final barColor  = isPos ? tp.getDangerColor() : teal;
              final barWidth  = maxAbs > 0 ? (shap.abs() / maxAbs).clamp(0.0, 1.0) : 0.0;
              final direction = isPos ? 'Pushed toward' : 'Pushed against';
              return Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Row(children: [
                  SizedBox(
                    width: 90,
                    child: Text(direction,
                        style: TextStyle(fontSize: 10, color: barColor,
                            fontWeight: FontWeight.w600)),
                  ),
                  const SizedBox(width: 6),
                  SizedBox(
                    width: 130,
                    child: Text(label,
                        style: TextStyle(fontSize: 11, color: _textColor),
                        overflow: TextOverflow.ellipsis),
                  ),
                  const SizedBox(width: 8),
                  SizedBox(
                    width: 80,
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(2),
                      child: LinearProgressIndicator(
                        value: barWidth,
                        color: barColor.withValues(alpha: 0.75),
                        backgroundColor: barColor.withValues(alpha: 0.10),
                        minHeight: 6,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(value.toStringAsFixed(3),
                      style: TextStyle(fontSize: 10, color: _mutedColor,
                          fontFamily: 'Courier Prime')),
                ]),
              );
            }),
          ],
        );
    }
  }

  // ── Fetch SHAP explanation ─────────────────────────────────────────────────
  Future<void> _fetchExplain(ThreatEntry entry) async {
    if (entry.flowId == null) return;
    setState(() => _explainState[entry.id] = const _ExplainState(_ExplainStatus.loading));

    final p = Provider.of<ThreatMatrixProvider>(context, listen: false);
    final data = await p.fetchExplanation(entry.flowId!);

    if (!mounted) return;

    if (data == null) {
      setState(() => _explainState[entry.id] = const _ExplainState(_ExplainStatus.expired));
      return;
    }

    // Extract top 3 features for the predicted class
    final shapValues = data['shap_values'] as Map<String, dynamic>?;
    final predictedClass = data['predicted_class'] as String?;

    if (shapValues == null || predictedClass == null) {
      setState(() => _explainState[entry.id] = const _ExplainState(_ExplainStatus.error));
      return;
    }

    final classEntries = shapValues[predictedClass] as List<dynamic>?;
    if (classEntries == null || classEntries.isEmpty) {
      setState(() => _explainState[entry.id] = const _ExplainState(_ExplainStatus.error));
      return;
    }

    // Already sorted by |shap| descending from backend — take top 5
    final top5 = classEntries.take(5).map((e) => {
      'feature': e['feature'] as String,
      'value':   (e['value']  as num).toDouble(),
      'shap':    (e['shap']   as num).toDouble(),
    }).toList();

    setState(() => _explainState[entry.id] = _ExplainState(_ExplainStatus.loaded, top5));
  }

  // ── Detail panel sub-widgets ──────────────────────────────────────────────

  Widget _detailSectionLabel(String text, IconData icon, Color color) =>
      Row(children: [
        Container(
          padding: const EdgeInsets.all(4),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.10),
            borderRadius: BorderRadius.circular(4),
          ),
          child: Icon(icon, size: 11, color: color),
        ),
        const SizedBox(width: 6),
        Text(text,
            style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
                color: color, letterSpacing: 0.7)),
      ]);

  Widget _detailRow(String label, String value, {required bool mono}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 5),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SizedBox(
            width: 82,
            child: Text(label,
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                    color: _mutedColor)),
          ),
          Expanded(child: Text(value,
              style: TextStyle(fontSize: 11, color: _textColor,
                  fontFamily: mono ? 'Courier Prime' : null),
              overflow: TextOverflow.visible)),
        ]),
      );

  Widget _pipelinePhaseBox({
    required String phase,
    required String label,
    required String result,
    required String? confidence,
    required double? confValue,
    required Color color,
    required IconData icon,
  }) {
    return Container(
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(7),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Icon(icon, size: 11, color: color),
          const SizedBox(width: 5),
          Text(phase,
              style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800,
                  color: color, letterSpacing: 0.6)),
          const Spacer(),
          if (confidence != null)
            Text(confidence,
                style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                    color: color, fontFamily: 'Courier Prime')),
        ]),
        const SizedBox(height: 3),
        Text(label,
            style: TextStyle(fontSize: 10, color: _mutedColor)),
        const SizedBox(height: 6),
        Text(result,
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700,
                color: _textColor, fontFamily: 'Courier Prime'),
            overflow: TextOverflow.ellipsis),
        if (confValue != null) ...[
          const SizedBox(height: 6),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: confValue.clamp(0.0, 1.0),
              minHeight: 3,
              backgroundColor: color.withValues(alpha: 0.12),
              valueColor: AlwaysStoppedAnimation<Color>(color),
            ),
          ),
        ],
      ]),
    );
  }

  Widget _pipelineArrow() => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 6),
    child: Icon(Icons.chevron_right_rounded, size: 18, color: _mutedColor),
  );

  Widget _frameworkBadge(String text, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.10),
      borderRadius: BorderRadius.circular(4),
      border: Border.all(color: color.withValues(alpha: 0.35)),
    ),
    child: Text(text,
        style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800,
            color: color, letterSpacing: 0.6)),
  );

  Widget _panelDivider() => Container(
    width: 1,
    margin: const EdgeInsets.symmetric(horizontal: 14),
    color: _borderColor,
  );

} // ← _DashboardPageState ends here

// ── Clear Log Button — always visible, hover feedback even when disabled ──────
class _ClearLogButton extends StatefulWidget {
  final bool enabled;
  final Color dangerColor;
  final Color mutedColor;
  final Future<void> Function() onPressed;

  const _ClearLogButton({
    required this.enabled,
    required this.dangerColor,
    required this.mutedColor,
    required this.onPressed,
  });

  @override
  State<_ClearLogButton> createState() => _ClearLogButtonState();
}

class _ClearLogButtonState extends State<_ClearLogButton> {
  bool _hovered = false;
  bool _pressed = false;

  @override
  Widget build(BuildContext context) {
    final color  = widget.enabled ? widget.dangerColor : widget.mutedColor;
    final alpha  = widget.enabled
        ? (_hovered ? 0.12 : 0.0)
        : (_hovered ? 0.06 : 0.0);  // subtle tint even when disabled
    final border = widget.enabled
        ? (_hovered ? color.withValues(alpha: 0.80) : color.withValues(alpha: 0.55))
        : (_hovered ? color.withValues(alpha: 0.40) : color.withValues(alpha: 0.25));

    return MouseRegion(
      cursor: widget.enabled
          ? SystemMouseCursors.click
          : SystemMouseCursors.forbidden,
      onEnter: (_) => setState(() => _hovered = true),
      onExit:  (_) => setState(() { _hovered = false; _pressed = false; }),
      child: GestureDetector(
        onTapDown:   (_) { if (widget.enabled) setState(() => _pressed = true); },
        onTapUp:     (_) => setState(() => _pressed = false),
        onTapCancel: ()  => setState(() => _pressed = false),
        onTap: widget.enabled ? widget.onPressed : null,
        child: AnimatedScale(
          scale: _pressed ? 0.96 : (_hovered && widget.enabled ? 1.02 : 1.0),
          duration: const Duration(milliseconds: 100),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
            decoration: BoxDecoration(
              color: color.withValues(alpha: alpha),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: border, width: 1.5),
              boxShadow: widget.enabled && _hovered
                  ? [BoxShadow(color: color.withValues(alpha: 0.22),
                      blurRadius: 10, offset: const Offset(0, 3))]
                  : [],
            ),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.delete_sweep_rounded, size: 14, color: color),
              const SizedBox(width: 5),
              Text('Clear',
                  style: TextStyle(fontSize: 13, color: color,
                      fontWeight: FontWeight.w600)),
            ]),
          ),
        ),
      ),
    );
  }
}

// ─── Shared confirm dialog ────────────────────────────────────────────────────

Future<bool> _showConfirmDialog({
  required BuildContext context,
  required ThemeProvider tp,
  required String title,
  required String message,
  String confirmLabel = 'Delete',
  Color? confirmColor,
  IconData icon = Icons.warning_amber_rounded,
}) async {
  final danger = confirmColor ?? tp.getDangerColor();
  final result = await showDialog<bool>(
    context: context,
    barrierDismissible: true,
    builder: (_) => Dialog(
      backgroundColor: tp.getCardColor(),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      insetPadding: const EdgeInsets.symmetric(horizontal: 80, vertical: 60),
      child: SizedBox(
        width: 400,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(28, 28, 28, 24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(
              width: 60, height: 60,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: danger.withValues(alpha: 0.12),
                border: Border.all(color: danger.withValues(alpha: 0.3), width: 1.5),
              ),
              child: Icon(icon, color: danger, size: 30),
            ),
            const SizedBox(height: 18),
            Text(title,
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold,
                    color: tp.getTextColor(), fontFamily: 'Courier Prime'),
                textAlign: TextAlign.center),
            const SizedBox(height: 10),
            Text(message,
                style: TextStyle(fontSize: 13, color: tp.getTextSecondaryColor(), height: 1.5),
                textAlign: TextAlign.center),
            const SizedBox(height: 24),
            Divider(color: tp.getBorderColor(), height: 1),
            const SizedBox(height: 18),
            Row(children: [
              Expanded(
                child: _HoverButton(
                  onPressed: () => Navigator.pop(context, false),
                  color: tp.getBorderColor(),
                  textColor: tp.getTextMutedColor(),
                  outlined: true,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  child: const Center(
                    child: Text('Cancel',
                        textAlign: TextAlign.center,
                        style: TextStyle(fontWeight: FontWeight.w600)),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _HoverButton(
                  onPressed: () => Navigator.pop(context, true),
                  color: danger,
                  textColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  child: Center(
                    child: Text(confirmLabel,
                        textAlign: TextAlign.center,
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                  ),
                ),
              ),
            ]),
          ]),
        ),
      ),
    ),
  );
  return result ?? false;
}

// ─── Hover Button ─────────────────────────────────────────────────────────────
// Modern button: AnimatedScale (press shrink / hover lift) + shadow bloom.
// The borderRadius is always 8 — no need to parameterise it.

class _HoverButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final Widget child;
  final Color color;
  final Color textColor;
  final EdgeInsetsGeometry padding;
  final bool outlined;

  const _HoverButton({
    required this.onPressed,
    required this.child,
    required this.color,
    required this.textColor,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
    this.outlined = false,
  });

  @override
  State<_HoverButton> createState() => _HoverButtonState();
}

class _HoverButtonState extends State<_HoverButton> {
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
        ? (_hovered ? widget.color.withValues(alpha: 0.09) : Colors.transparent)
        : dis  ? widget.color.withValues(alpha: 0.38)
        : _pressed ? _shift(widget.color, 0.06)
        : _hovered ? _shift(widget.color, -0.07)
        : widget.color;

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
          scale: _pressed ? 0.97 : (_hovered ? 1.02 : 1.0),
          duration: const Duration(milliseconds: 100),
          curve: Curves.easeOutCubic,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            curve: Curves.easeOutCubic,
            padding: widget.padding,
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: widget.outlined
                    ? widget.color
                    : Colors.transparent,
                width: 1.5,
              ),
              boxShadow: !widget.outlined && _hovered && !dis
                  ? [BoxShadow(
                      color: widget.color.withValues(alpha: 0.26),
                      blurRadius: 14,
                      spreadRadius: 0,
                      offset: const Offset(0, 4),
                    )]
                  : [],
            ),
            child: DefaultTextStyle(
              style: TextStyle(
                color: widget.outlined ? widget.color : widget.textColor,
                fontWeight: FontWeight.w600,
                fontSize: 13,
                letterSpacing: 0.1,
              ),
              child: widget.child,
            ),
          ),
        ),
      ),
    );
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// _PhaseTab — data-only config class, one instance per phase tab.
// Must be top-level (Dart does not allow classes inside other classes).
// ─────────────────────────────────────────────────────────────────────────────

class _PhaseTab {
  final String code;
  final String shortLabel;
  final String fullLabel;
  final String description;
  final PhaseMetrics metrics;
  final bool isLoading;
  final String? noteOverride;
  final Color accent;
  final ThemeProvider tp;
  final Color mutedColor;
  final Color labelColor;
  final Color borderColor;

  const _PhaseTab({
    required this.code,
    required this.shortLabel,
    required this.fullLabel,
    required this.description,
    required this.metrics,
    required this.isLoading,
    required this.accent,
    required this.tp,
    required this.mutedColor,
    required this.labelColor,
    required this.borderColor,
    this.noteOverride,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// _PhaseMetricsTabs — renders the three clickable phase tabs and their
// metric chips inside the Model Performance card.
// Must be top-level (Dart does not allow classes inside other classes).
// ─────────────────────────────────────────────────────────────────────────────

class _PhaseMetricsTabs extends StatefulWidget {
  final List<_PhaseTab> phases;
  const _PhaseMetricsTabs({required this.phases});

  @override
  State<_PhaseMetricsTabs> createState() => _PhaseMetricsTabsState();
}

class _PhaseMetricsTabsState extends State<_PhaseMetricsTabs> {
  int _selected = 0;

  String _fmt(double? v) =>
      v != null ? '${(v * 100).toStringAsFixed(1)}%' : '—';

  Color _mColor(double? v, Color accent, Color muted) {
    if (v == null) return muted;
    if (v >= 0.90) return accent;
    if (v >= 0.75) return const Color(0xFFFFD600);
    return const Color(0xFFFF5252);
  }

  @override
  Widget build(BuildContext context) {
    final tab = widget.phases[_selected];

    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

      // ── Tab selector ────────────────────────────────────────────────────────
      Row(children: widget.phases.asMap().entries.map((entry) {
        final i = entry.key;
        final t = entry.value;
        final isActive = _selected == i;
        return Padding(
          padding: const EdgeInsets.only(right: 8),
          child: GestureDetector(
            onTap: () => setState(() => _selected = i),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
              decoration: BoxDecoration(
                color: isActive
                    ? t.accent.withValues(alpha: 0.12)
                    : Colors.transparent,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                  color: isActive
                      ? t.accent.withValues(alpha: 0.5)
                      : t.borderColor,
                ),
              ),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                Container(
                  width: 7, height: 7,
                  decoration: BoxDecoration(
                    color: isActive ? t.accent : t.mutedColor,
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 7),
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(t.code,
                      style: TextStyle(
                          fontSize: 9, fontWeight: FontWeight.w800,
                          color: isActive ? t.accent : t.mutedColor,
                          letterSpacing: 0.6, fontFamily: 'Courier Prime')),
                  Text(t.shortLabel,
                      style: TextStyle(
                          fontSize: _fsCaption, fontWeight: FontWeight.w500,
                          color: isActive ? t.accent : t.mutedColor)),
                ]),
              ]),
            ),
          ),
        );
      }).toList()),

      const SizedBox(height: 14),

      // ── Description ────────────────────────────────────────────────────────
      if (tab.description.isNotEmpty) ...[
        Text(tab.description,
            style: TextStyle(fontSize: _fsCaption, color: tab.mutedColor)),
        const SizedBox(height: 12),
      ],

      // ── Four core metric chips ──────────────────────────────────────────────
      _buildChipRow(tab),

      // ── ROC-AUC / PR-AUC row ───────────────────────────────────────────────
      if (tab.metrics.rocAuc != null || tab.metrics.prAuc != null) ...[
        const SizedBox(height: 10),
        _buildAucRow(tab),
      ],

      // ── Caveat note (Phase 3 open-world explanation) ───────────────────────
      if (tab.noteOverride != null) ...[
        const SizedBox(height: 10),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
          decoration: BoxDecoration(
            color: tab.accent.withValues(alpha: 0.06),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: tab.accent.withValues(alpha: 0.25)),
          ),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Icon(Icons.info_outline, size: 13, color: tab.accent),
            const SizedBox(width: 7),
            Expanded(child: Text(tab.noteOverride!,
                style: TextStyle(fontSize: _fsCaption, color: tab.mutedColor))),
          ]),
        ),
      ],
    ]);
  }

  Widget _buildChipRow(_PhaseTab tab) {
    final m = tab.metrics;
    final chips = [
      ('Accuracy',  _fmt(m.accuracy),  _mColor(m.accuracy,  tab.accent, tab.mutedColor), Icons.analytics_outlined),
      ('Precision', _fmt(m.precision), _mColor(m.precision, tab.accent, tab.mutedColor), Icons.gps_fixed_outlined),
      ('Recall',    _fmt(m.recall),    _mColor(m.recall,    tab.accent, tab.mutedColor), Icons.radar_outlined),
      ('F1 Score',  _fmt(m.f1Score),   _mColor(m.f1Score,   tab.accent, tab.mutedColor), Icons.balance_outlined),
    ];

    return Row(children: chips.asMap().entries.map((entry) {
      final i = entry.key;
      final c = entry.value;
      return Expanded(
        child: Container(
          margin: EdgeInsets.only(right: i < chips.length - 1 ? 10.0 : 0.0),
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
          decoration: BoxDecoration(
            color: c.$3.withValues(alpha: 0.07),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: c.$3.withValues(alpha: 0.25)),
          ),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Icon(c.$4, color: c.$3, size: 14),
              const SizedBox(width: 6),
              Text(c.$1,
                  style: TextStyle(fontSize: _fsCaption,
                      fontWeight: FontWeight.w800, color: tab.labelColor)),
            ]),
            const SizedBox(height: 8),
            tab.isLoading
                ? SizedBox(width: 16, height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2, color: c.$3))
                : Text(c.$2,
                    style: TextStyle(
                        fontSize: _fsMetricValue, fontWeight: FontWeight.bold,
                        color: c.$3, fontFamily: 'Courier Prime', height: 1.0)),
          ]),
        ),
      );
    }).toList());
  }

  Widget _buildAucRow(_PhaseTab tab) {
    final m = tab.metrics;
    final items = [
      if (m.rocAuc != null) ('ROC-AUC', _fmt(m.rocAuc), m.rocAuc!),
      if (m.prAuc  != null) ('PR-AUC',  _fmt(m.prAuc),  m.prAuc!),
    ];

    return Row(children: items.asMap().entries.map((entry) {
      final i  = entry.key;
      final it = entry.value;
      return Expanded(
        child: Container(
          margin: EdgeInsets.only(right: i < items.length - 1 ? 10.0 : 0.0),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
          decoration: BoxDecoration(
            color: tab.accent.withValues(alpha: 0.05),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: tab.accent.withValues(alpha: 0.18)),
          ),
          child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Text(it.$1,
                style: TextStyle(fontSize: _fsCaption,
                    fontWeight: FontWeight.w700, color: tab.labelColor)),
            Text(it.$2,
                style: TextStyle(
                    fontSize: _fsBody, fontWeight: FontWeight.bold,
                    color: _mColor(it.$3, tab.accent, tab.mutedColor),
                    fontFamily: 'Courier Prime')),
          ]),
        ),
      );
    }).toList());
  }
}

// ─── Time-Series Painter ──────────────────────────────────────────────────────

class _TimeSeriesPainter extends CustomPainter {
  final List<FlowDataPoint> dataPoints;
  final Color threatColor, benignColor, uncertainColor, gridColor;
  final bool isDark;

  const _TimeSeriesPainter({
    required this.dataPoints, required this.threatColor,
    required this.benignColor, required this.uncertainColor,
    required this.gridColor, required this.isDark,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (dataPoints.isEmpty) return;
    final maxY = dataPoints.map((d) => d.threats + d.benign + d.uncertain)
        .fold<int>(0, math.max).toDouble();
    final effMax = maxY == 0 ? 10.0 : maxY * 1.2;

    final gridPaint = Paint()..color = gridColor.withValues(alpha: 0.4)..strokeWidth = 0.5;
    for (int i = 0; i <= 4; i++) {
      final y = size.height * i / 4;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
    _series(canvas, size, dataPoints.map((d) => d.threats.toDouble()).toList(),
        effMax, threatColor, filled: true);
    _series(canvas, size, dataPoints.map((d) => d.benign.toDouble()).toList(),
        effMax, benignColor, filled: false);
    _series(canvas, size, dataPoints.map((d) => d.uncertain.toDouble()).toList(),
        effMax, uncertainColor, filled: false);
  }

  void _series(Canvas canvas, Size size, List<double> vals, double maxY,
      Color color, {required bool filled}) {
    if (vals.length < 2) return;
    final path = Path();
    final fill = Path();
    for (int i = 0; i < vals.length; i++) {
      final x = size.width * i / (vals.length - 1);
      final y = size.height - size.height * vals[i] / maxY;
      if (i == 0) { path.moveTo(x, y); fill.moveTo(x, size.height); fill.lineTo(x, y); }
      else { path.lineTo(x, y); fill.lineTo(x, y); }
    }
    if (filled) {
      fill.lineTo(size.width, size.height); fill.close();
      canvas.drawPath(fill, Paint()
        ..color = color.withValues(alpha: 0.08)..style = PaintingStyle.fill);
    }
    canvas.drawPath(path, Paint()
      ..color = color..strokeWidth = 1.5..style = PaintingStyle.stroke
      ..strokeJoin = StrokeJoin.round..strokeCap = StrokeCap.round);
  }

  @override
  bool shouldRepaint(_TimeSeriesPainter o) => o.dataPoints != dataPoints;
}

// ─── Pulsing Dot ──────────────────────────────────────────────────────────────

class _PulsingDot extends StatefulWidget {
  final Color color;
  const _PulsingDot({required this.color});
  @override
  State<_PulsingDot> createState() => _PulsingDotState();
}

class _PulsingDotState extends State<_PulsingDot> with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double> _anim;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 900))
      ..repeat(reverse: true);
    _anim = Tween<double>(begin: 0.4, end: 1.0)
        .animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => FadeTransition(
    opacity: _anim,
    child: Container(width: 7, height: 7,
        decoration: BoxDecoration(color: widget.color, shape: BoxShape.circle)),
  );
}