// ThreatMatrix Dashboard: MITRE ATT&CK PAGE
//
// CHANGE: Entries are no longer hardcoded.
// On init, the page calls provider.fetchMitreMapping() → GET /mitre, which
// returns { "phase_2": {...}, "phase_3": {...} } straight from
// threatmatrix_mitre_nist_mapping.py (the auto-generated file).
// _MitreEntry.fromJson() maps each dict entry to the display model.
// This means regenerating the Python mapping auto-updates this page too.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'threatmatrix_flutter_theme_provider.dart';
import 'threatmatrix_provider.dart';

// ─── MITRE ATT&CK Page ───────────────────────────────────────────────────────

class MitreAttackPage extends StatefulWidget {
  const MitreAttackPage({super.key});
  @override
  State<MitreAttackPage> createState() => _MitreAttackPageState();
}

class _MitreAttackPageState extends State<MitreAttackPage>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final Set<String> _expanded = {};

  // ── Data state ──────────────────────────────────────────────────────────────
  bool _loading = true;
  String? _error;
  List<_MitreEntry> _phase2Entries = [];
  List<_MitreEntry> _phase3Entries = [];

  // ── Color helpers (same tokens as DashboardPage) ────────────────────────────
  ThemeProvider get tp      => context.read<ThemeProvider>();
  Color get _textColor      => tp.isDarkMode ? Colors.white            : const Color(0xFF111827);
  Color get _mutedColor     => tp.isDarkMode ? const Color(0xFF6B7280) : const Color(0xFF6B7280);
  Color get _labelColor     => tp.isDarkMode ? const Color(0xFFB8C0CC) : const Color(0xFF374151);
  Color get _cardBg         => tp.isDarkMode ? const Color(0xFF1A1E28) : Colors.white;
  Color get _pageBg         => tp.isDarkMode ? const Color(0xFF111318) : const Color(0xFFE8EBF0);
  Color get _borderColor    => tp.isDarkMode ? const Color(0xFF252C3B) : const Color(0xFFCFD8DC);
  Color get _blue           => tp.isDarkMode ? const Color(0xFF2196F3) : const Color(0xFF1565C0);
  List<BoxShadow>? get _shadow => tp.isDarkMode
      ? null
      : [BoxShadow(color: Colors.black.withValues(alpha: 0.08), blurRadius: 8, offset: const Offset(0, 2))];

  BoxDecoration _card() => BoxDecoration(
    color: _cardBg,
    borderRadius: BorderRadius.circular(10),
    border: Border.all(color: _borderColor),
    boxShadow: _shadow,
  );

  Color _sevColor(String s) => switch (s.toLowerCase()) {
    'critical'    => tp.getDangerColor(),
    'high'        => tp.getWarningColor(),
    'medium'      => _blue,
    'medium-high' => tp.getWarningColor(),
    'low'         => tp.getSuccessColor(),
    _             => _mutedColor,
  };

  // ── Lifecycle ───────────────────────────────────────────────────────────────

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _tabController.addListener(() => setState(() {}));
    // Defer until after first frame so context.read() is safe.
    WidgetsBinding.instance.addPostFrameCallback((_) => _loadMitreData());
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  // ── Data loader ─────────────────────────────────────────────────────────────

  Future<void> _loadMitreData() async {
    setState(() { _loading = true; _error = null; });
    try {
      // fetchMitreMapping() calls GET /mitre via ThreatMatrixApiService.
      final data = await context.read<ThreatMatrixProvider>().fetchMitreMapping();
      if (!mounted) return;
      if (data == null) throw Exception('Server returned null — is FastAPI running?');

      final p2raw = (data['phase_2'] as Map<String, dynamic>?) ?? {};
      final p3raw = (data['phase_3'] as Map<String, dynamic>?) ?? {};

      setState(() {
        // Map each dict key (class name) + its value (field map) into a display entry.
        _phase2Entries = p2raw.entries
            .map((e) => _MitreEntry.fromJson(
                  e.key,
                  e.value as Map<String, dynamic>,
                  'Phase 2 — Severity Classification',
                ))
            .toList();
        _phase3Entries = p3raw.entries
            .map((e) => _MitreEntry.fromJson(
                  e.key,
                  e.value as Map<String, dynamic>,
                  'Phase 3 — Fine-grained',
                ))
            .toList();
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  // ── Build ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    context.watch<ThemeProvider>();
    return ColoredBox(
      color: _pageBg,
      child: Column(children: [
        // Tab bar is always visible (even during load/error).
        _buildTabBar(),
        Expanded(
          child: _loading
              ? _buildLoading()
              : _error != null
                  ? _buildError()
                  : TabBarView(
                      controller: _tabController,
                      children: [
                        _buildEntryList(_phase2Entries),
                        _buildEntryList(_phase3Entries),
                      ],
                    ),
        ),
      ]),
    );
  }

  Widget _buildTabBar() => Container(
    color: _cardBg,
    padding: const EdgeInsets.fromLTRB(20, 0, 20, 0),
    child: TabBar(
      controller: _tabController,
      isScrollable: true,
      tabAlignment: TabAlignment.start,
      indicatorColor: tp.getSuccessColor(),
      indicatorWeight: 2.5,
      labelColor: tp.getSuccessColor(),
      unselectedLabelColor: _mutedColor,
      labelStyle: const TextStyle(
          fontSize: 13, fontWeight: FontWeight.w700, fontFamily: 'Courier Prime'),
      unselectedLabelStyle:
          const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
      dividerColor: _borderColor,
      tabs: const [
        Tab(text: 'Phase 2 — Severity Classification'),
        Tab(text: 'Phase 3 — Fine-grained'),
      ],
    ),
  );

  // Shown while GET /mitre is in-flight.
  Widget _buildLoading() => Center(
    child: Column(mainAxisSize: MainAxisSize.min, children: [
      CircularProgressIndicator(color: tp.getSuccessColor()),
      const SizedBox(height: 16),
      Text('Loading MITRE ATT\u0026CK data...',
          style: TextStyle(color: _mutedColor, fontSize: 13)),
    ]),
  );

  // Shown if the request failed. Retry button re-calls _loadMitreData().
  Widget _buildError() => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Icon(Icons.warning_amber_rounded, color: tp.getWarningColor(), size: 40),
        const SizedBox(height: 12),
        Text('Failed to load MITRE data',
            style: TextStyle(
                color: _textColor, fontSize: 15, fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        Text(_error ?? 'Unknown error',
            textAlign: TextAlign.center,
            style: TextStyle(color: _mutedColor, fontSize: 12)),
        const SizedBox(height: 20),
        ElevatedButton.icon(
          onPressed: _loadMitreData,
          icon: const Icon(Icons.refresh, size: 16),
          label: const Text('Retry'),
          style: ElevatedButton.styleFrom(backgroundColor: tp.getSuccessColor()),
        ),
      ]),
    ),
  );

  // ── Shared entry list builder ───────────────────────────────────────────────

  Widget _buildEntryList(List<_MitreEntry> entries) {
    if (entries.isEmpty) {
      return Center(
        child: Text('No entries', style: TextStyle(color: _mutedColor)),
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.all(20),
      itemCount: entries.length,
      separatorBuilder: (_, __) => const SizedBox(height: 12),
      itemBuilder: (_, i) => _buildCard(entries[i]),
    );
  }

  Widget _buildCard(_MitreEntry e) {
    final isOpen   = _expanded.contains(e.name);
    final sevColor = _sevColor(e.severity);

    return Container(
      decoration: _card(),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

        // ── Card header ───────────────────────────────────────────────────────
        InkWell(
          borderRadius: BorderRadius.circular(10),
          onTap: () => setState(() {
            if (isOpen) { _expanded.remove(e.name); }
            else        { _expanded.add(e.name); }
          }),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 14, 12, 14),
            child: Row(children: [
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text(e.name,
                        style: TextStyle(
                            fontSize: 16, fontWeight: FontWeight.bold,
                            color: _textColor, fontFamily: 'Courier Prime')),
                    if (e.isHeldOut) ...[
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                        decoration: BoxDecoration(
                          color: tp.getWarningColor().withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: tp.getWarningColor().withValues(alpha: 0.4)),
                        ),
                        child: Text('HELD-OUT NOVEL',
                            style: TextStyle(
                                fontSize: 10, fontWeight: FontWeight.w800,
                                color: tp.getWarningColor(), letterSpacing: 0.5)),
                      ),
                    ],
                  ]),
                  const SizedBox(height: 4),
                  Text(e.phaseLabel,
                      style: TextStyle(fontSize: 12, color: _mutedColor)),
                  const SizedBox(height: 8),
                  Wrap(spacing: 6, children: [
                    _chip(e.tier, tp.getSuccessColor()),
                    if (e.protocol != null) _chip(e.protocol!, tp.getSuccessColor()),
                  ]),
                ]),
              ),
              const SizedBox(width: 12),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                decoration: BoxDecoration(
                  color: sevColor.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: sevColor.withValues(alpha: 0.35)),
                ),
                child: Text(e.severity,
                    style: TextStyle(
                        fontSize: 12, fontWeight: FontWeight.w700, color: sevColor)),
              ),
              const SizedBox(width: 8),
              Icon(isOpen ? Icons.expand_less : Icons.expand_more,
                  color: _mutedColor, size: 20),
            ]),
          ),
        ),

        // ── Expanded detail panel ─────────────────────────────────────────────
        if (isOpen) ...[
          Divider(color: _borderColor, height: 1),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

              if (e.tactics.isNotEmpty) ...[
                _detailLabel('MITRE Tactics'),
                ...e.tactics.map(_bullet),
                const SizedBox(height: 10),
              ],

              if (e.techniques.isNotEmpty) ...[
                _detailLabel('MITRE Techniques'),
                ...e.techniques.map(_bullet),
                const SizedBox(height: 10),
              ],

              if (e.mitigations.isNotEmpty) ...[
                _detailLabel('Mitigations'),
                ...e.mitigations.map(_bullet),
                const SizedBox(height: 10),
              ],

              _detailLabel('NIST SP 800-61 Rev. 2'),
              _infoRow('Category', e.nistCategory),
              _infoRow('Severity', e.nistSeverity),
              _infoRow('Response', e.nistResponse),
              const SizedBox(height: 10),

              _detailLabel('Training Source'),
              Padding(
                padding: const EdgeInsets.only(left: 8, top: 2),
                child: Text(e.trainingSource,
                    style: TextStyle(
                        fontSize: 12, color: _mutedColor,
                        fontFamily: 'Courier Prime')),
              ),

              if (e.owasp != null) ...[
                const SizedBox(height: 10),
                _detailLabel('OWASP Reference'),
                Padding(
                  padding: const EdgeInsets.only(left: 8, top: 2),
                  child: Text(e.owasp!,
                      style: TextStyle(fontSize: 12, color: _blue)),
                ),
              ],

              if (e.urls.isNotEmpty) ...[
                const SizedBox(height: 12),
                Wrap(
                  spacing: 6, runSpacing: 6,
                  children: e.urls.map(_urlChip).toList(),
                ),
              ],

              if (e.notes != null) ...[
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: tp.getWarningColor().withValues(alpha: 0.07),
                    borderRadius: BorderRadius.circular(7),
                    border: Border.all(color: tp.getWarningColor().withValues(alpha: 0.3)),
                  ),
                  child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Icon(Icons.info_outline, size: 14, color: tp.getWarningColor()),
                    const SizedBox(width: 7),
                    Expanded(child: Text(e.notes!,
                        style: TextStyle(fontSize: 12, color: _labelColor, height: 1.5))),
                  ]),
                ),
              ],

            ]),
          ),
        ],
      ]),
    );
  }

  // ── Small widget helpers (unchanged from original) ──────────────────────────

  Widget _chip(String label, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
    decoration: BoxDecoration(
      color: color.withValues(alpha: 0.08),
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: color.withValues(alpha: 0.35)),
    ),
    child: Text(label,
        style: TextStyle(fontSize: 12, color: color, fontWeight: FontWeight.w600)),
  );

  Widget _detailLabel(String text) => Padding(
    padding: const EdgeInsets.only(bottom: 4),
    child: Text(text,
        style: TextStyle(
            fontSize: 12, fontWeight: FontWeight.w700,
            color: _labelColor, letterSpacing: 0.3)),
  );

  Widget _bullet(String text) => Padding(
    padding: const EdgeInsets.only(left: 8, top: 2, bottom: 2),
    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Padding(
        padding: const EdgeInsets.only(top: 5),
        child: Container(
            width: 4, height: 4,
            decoration: BoxDecoration(color: _mutedColor, shape: BoxShape.circle)),
      ),
      const SizedBox(width: 7),
      Expanded(child: Text(text, style: TextStyle(fontSize: 13, color: _labelColor))),
    ]),
  );

  Widget _infoRow(String label, String value) => Padding(
    padding: const EdgeInsets.only(left: 8, top: 2, bottom: 2),
    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SizedBox(
        width: 72,
        child: Text(label,
            style: TextStyle(
                fontSize: 12, color: _mutedColor, fontWeight: FontWeight.w600)),
      ),
      Expanded(child: Text(value, style: TextStyle(fontSize: 12, color: _labelColor))),
    ]),
  );

  // URL chips: strip https:// prefix for compact display (matching original style).
  Widget _urlChip(String url) {
    final display = url.replaceFirst(RegExp(r'^https?://'), '');
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: tp.getSuccessColor().withValues(alpha: 0.4)),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(Icons.open_in_new, size: 11, color: tp.getSuccessColor()),
        const SizedBox(width: 4),
        Text(display, style: TextStyle(fontSize: 11, color: tp.getSuccessColor())),
      ]),
    );
  }
}

// ── MITRE entry data class ────────────────────────────────────────────────────

class _MitreEntry {
  final String name;
  final String phaseLabel;
  final String severity;
  final String tier;
  final String? protocol;
  final bool isHeldOut;
  final List<String> tactics;
  final List<String> techniques;
  final List<String> mitigations;
  final String nistCategory;
  final String nistSeverity;
  final String nistResponse;
  final String trainingSource;
  final String? owasp;
  final List<String> urls;
  final String? notes;

  const _MitreEntry({
    required this.name,
    required this.phaseLabel,
    required this.severity,
    required this.tier,
    this.protocol,
    this.isHeldOut = false,
    required this.tactics,
    required this.techniques,
    required this.mitigations,
    required this.nistCategory,
    required this.nistSeverity,
    required this.nistResponse,
    required this.trainingSource,
    this.owasp,
    required this.urls,
    this.notes,
  });

  // ── Factory: maps one entry from the /mitre JSON response ──────────────────
  //
  // JSON shape (from PHASE_2_TIER_MAPPING / PHASE_3_CLASS_MAPPING):
  //   mitre_techniques       : List<String>
  //   mitre_tactics          : List<String>
  //   mitre_mitigations      : List<String>
  //   mitre_urls             : List<String>  — full https:// URLs
  //   nist_sp80061_category  : String        — NOTE: not nist_category
  //   nist_severity          : String
  //   nist_response          : String
  //   training_source        : String
  //   phase_2_tier           : String?       — Phase 3 entries only
  //   protocol               : String?       — Phase 3 entries only
  //   owasp                  : String?
  //   honest_caveat          : String?       — primary notes field
  //   notes                  : String?       — fallback notes field
  //   novel_in_phase_3       : bool          — true = held-out class

  factory _MitreEntry.fromJson(
    String key,
    Map<String, dynamic> json,
    String phaseLabel,
  ) {
    List<String> toStrList(dynamic v) =>
        v == null ? [] : (v as List).map((e) => e.toString()).toList();

    // Underscores in class names become spaces: "Credential_Abuse" → "Credential Abuse"
    final displayName = key.replaceAll('_', ' ');

    final isHeldOut = json['novel_in_phase_3'] as bool? ?? false;

    // Tier logic:
    //   Phase 3 entries carry phase_2_tier ("Reconnaissance", "Credential_Abuse", etc.).
    //   Phase 2 entries have no tier field — the dict key IS the tier name.
    //   UNCERTAIN / Benign / UNKNOWN have no meaningful tier.
    final p2tier = json['phase_2_tier'] as String?;
    final String tier;
    if (p2tier != null) {
      // Use temp var to avoid nested quotes inside string interpolation.
      final tierLabel = p2tier.replaceAll('_', ' ');
      tier = 'Tier: $tierLabel';
    } else if (key == 'UNCERTAIN' || key == 'Benign' || key == 'UNKNOWN') {
      tier = 'Tier: —';
    } else {
      final tierLabel = key.replaceAll('_', ' ');
      tier = 'Tier: $tierLabel';
    }

    return _MitreEntry(
      name:           displayName,
      phaseLabel:     isHeldOut ? '$phaseLabel · HELD-OUT NOVEL' : phaseLabel,
      severity:       json['nist_severity']         as String? ?? 'Medium',
      tier:           tier,
      protocol:       json['protocol']              as String?,
      isHeldOut:      isHeldOut,
      tactics:        toStrList(json['mitre_tactics']),
      techniques:     toStrList(json['mitre_techniques']),
      mitigations:    toStrList(json['mitre_mitigations']),
      // Field is nist_sp80061_category in the mapping file — not nist_category.
      nistCategory:   json['nist_sp80061_category'] as String? ?? '—',
      nistSeverity:   json['nist_severity']         as String? ?? '—',
      nistResponse:   json['nist_response']         as String? ?? '—',
      trainingSource: json['training_source']       as String? ?? '—',
      owasp:          json['owasp']                 as String?,
      urls: toStrList(json['mitre_urls'])
          .map((u) => u.replaceFirst(RegExp(r'^https?://'), ''))
          .toList(),
      // honest_caveat is the primary notes field; fall back to notes.
      notes: json['honest_caveat'] as String? ?? json['notes'] as String?,
    );
  }
}