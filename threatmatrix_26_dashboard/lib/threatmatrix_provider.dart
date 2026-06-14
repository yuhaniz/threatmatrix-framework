// threatmatrix_provider.dart
// WebSocket-driven provider with time-series data, risk scoring, incident correlation.

import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import 'config/threatmatrix_api_config.dart';
import 'threatmatrix_api_service.dart';

// ── Time-series data point ────────────────────────────────────────────────────
class FlowDataPoint {
  final DateTime time;
  final int threats;
  final int benign;
  final int uncertain;
  const FlowDataPoint({required this.time, required this.threats, required this.benign, required this.uncertain});
}

// ── Correlated incident ───────────────────────────────────────────────────────
class ThreatIncident {
  final String incidentId;
  final List<ThreatEntry> entries;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final String dominantType;
  final String severity;
  const ThreatIncident({
    required this.incidentId,
    required this.entries,
    required this.firstSeen,
    required this.lastSeen,
    required this.dominantType,
    required this.severity,
  });
  int get count => entries.length;

  /// Human-readable label shown in the Reports "Correlated Incidents" panel.
  /// Terminology follows NIST SP 800-61 Rev.2 ("incident cluster", "activity
  /// set") and MITRE ATT&CK tactic naming conventions.
  /// OSR-rejected incidents use dominantType == 'UNKNOWN' — they are surfaced
  /// as unclassified activity and must never be attributed to a confirmed
  /// threat actor or technique.
  String get description {
    if (dominantType == 'UNKNOWN') {
      return count == 1
          ? '1 unclassified flow — OSR rejection, pending analyst triage'
          : '$count unclassified flows — OSR rejection, pending analyst triage';
    }
    final label = _activitySetLabel(dominantType);
    return count == 1 ? '1 event — $label' : '$count correlated events — $label';
  }

  /// Maps a Phase-3 class label to an industry-standard incident descriptor.
  ///
  /// Naming conventions:
  ///   "Activity Set"      — NIST SP 800-61 / CISA term for a cluster of
  ///                         related reconnaissance or scanning events that
  ///                         share a source or TTPs but have not yet caused
  ///                         confirmed impact.
  ///   "Incident Cluster"  — NIST SP 800-61 term for a correlated group of
  ///                         events that constitute or contribute to an active
  ///                         security incident (exploitation, credential abuse).
  static String _activitySetLabel(String type) {
    final t = type.toLowerCase();
    if (t.contains('sqli') || t.contains('sql_inj')) {
      return 'SQL Injection Incident Cluster [T1190]';
    }
    if (t.contains('brute') || t.contains('credential_abuse')) {
      return 'Credential Brute-Force Incident Cluster [T1110]';
    }
    if (t.contains('portscan') || t.contains('reconnaissance') || t.contains('recon')) {
      return 'Reconnaissance Activity Set [T1595]';
    }
    if (t.contains('active_exploit') || t.contains('exploit')) {
      return 'Initial Access Incident Cluster [T1190]';
    }
    if (t.contains('xss') || t.contains('cross_site')) {
      return 'Web Application Attack Cluster [T1059.007]';
    }
    if (t.contains('dos') || t.contains('denial')) {
      return 'Network Disruption Activity Set [T1498]';
    }
    // Fallback: use the raw label with neutral NIST framing.
    return '${type.replaceAll('_', ' ')} Incident Cluster';
  }
}

// ── Main provider ─────────────────────────────────────────────────────────────
class ThreatMatrixProvider extends ChangeNotifier {
  final ThreatMatrixApiService _api = ThreatMatrixApiService();

  HealthStatus _health = HealthStatus.unknown();
  DashboardStats _stats = DashboardStats.empty();
  final List<ThreatEntry> _threatLog = [];
  int _notificationCount = 0;
  String? _scanError;
  final List<double> _confidenceScores = [];
  int _threatCounter = 0;

  // Time-series: 1-minute buckets, last 30 minutes — driven by DATASET time.
  final List<FlowDataPoint> _timeSeries = [];
  int _bucketThreats = 0;
  int _bucketBenign = 0;
  int _bucketUncertain = 0;
  DateTime? _bucketStart; // null until the first event arrives

  // Incident correlation
  final List<ThreatIncident> _incidents = [];
  final List<ThreatEntry> _pendingCorrelation = [];
  Timer? _correlationTimer;

  double _riskScore = 0.0;
  ModelMetrics _modelMetrics = ModelMetrics.unavailable();

  // WebSocket
  WebSocketChannel? _wsChannel;
  bool _wsConnected = false;
  Timer? _reconnectTimer;
  Timer? _healthTimer;

  int _reconnectAttempts = 0;
  static const Duration _baseReconnectDelay = Duration(seconds: 2);
  static const Duration _maxReconnectDelay = Duration(seconds: 60);

  static const Duration _healthInterval = Duration(seconds: 30);
  static const Duration _bucketWidth = Duration(minutes: 1);
  static const Duration _correlationWindow = Duration(seconds: 60);
  static const int _maxBuckets = 30;

  // Getters
  HealthStatus get health => _health;
  DashboardStats get stats => _stats;
  List<ThreatEntry> get threatLog => List.unmodifiable(_threatLog);
  List<FlowDataPoint> get timeSeries => List.unmodifiable(_timeSeries);
  List<ThreatIncident> get incidents => List.unmodifiable(_incidents);
  double get riskScore => _riskScore;
  int get notificationCount => _notificationCount;
  String? get scanError => _scanError;
  bool get wsConnected => _wsConnected;
  bool get isScanning => false;
  double get scanProgress => 0.0;
  String get scanFileName => '';
  ModelMetrics get modelMetrics => _modelMetrics;
  String get systemStatusLabel => _health.isOnline ? 'Operational' : 'Offline';
  String get systemStatusSubtitle =>
      _wsConnected ? 'Live feed active' : 'Connecting to feed...';
  String get riskLabel {
    if (_riskScore >= 75) return 'Critical';
    if (_riskScore >= 50) return 'High';
    if (_riskScore >= 25) return 'Elevated';
    return 'Low';
  }

  Future<void> initialise() async {
    if (kDebugMode) {
      debugPrint('[ThreatMatrix] API base: ${ApiConfig.baseUrl}');
      debugPrint('[ThreatMatrix] WS URL:   ${ApiConfig.webSocketUrl}');
      debugPrint('[ThreatMatrix] secure:   ${ApiConfig.isSecure}');
    }
    await _checkHealth();
    await fetchMetrics();
    _connectWebSocket();
    _startHealthTimer();
  }

  Future<void> fetchMetrics() async {
    _modelMetrics = ModelMetrics.loading();
    notifyListeners();
    try {
      _modelMetrics = await _api.getMetrics();
    } catch (_) {
      _modelMetrics = ModelMetrics.unavailable();
    }
    notifyListeners();
  }

  Future<void> _checkHealth() async {
    try {
      _health = await _api.getHealth();
      _scanError = null;
    } catch (_) {
      _health = HealthStatus.offline();
    }
    notifyListeners();
  }

  void _startHealthTimer() {
    _healthTimer?.cancel();
    _healthTimer = Timer.periodic(_healthInterval, (_) => _checkHealth());
  }

  /// Bucket flushing is now driven by the EVENT timestamps themselves.
  /// When an event arrives whose dataset time crosses a bucket boundary,
  /// we close the open bucket and start a fresh one. This way replays of
  /// historic CSVs produce charts that span the dataset's actual time
  /// range — not the wall-clock minute the agent happened to run in.
  void _maybeAdvanceBucket(DateTime eventTime) {
    if (_bucketStart == null) {
      _bucketStart = eventTime;
      return;
    }
    while (eventTime.isAfter(_bucketStart!.add(_bucketWidth))) {
      _timeSeries.add(FlowDataPoint(
        time: _bucketStart!,
        threats: _bucketThreats,
        benign: _bucketBenign,
        uncertain: _bucketUncertain,
      ));
      if (_timeSeries.length > _maxBuckets) _timeSeries.removeAt(0);
      _bucketThreats = 0;
      _bucketBenign = 0;
      _bucketUncertain = 0;
      _bucketStart = _bucketStart!.add(_bucketWidth);
    }
  }

  void _connectWebSocket() {
    try {
      final url = ApiConfig.webSocketUrl;
      if (kDebugMode) debugPrint('[ThreatMatrix] WS connect → $url');
      _wsChannel = WebSocketChannel.connect(Uri.parse(url));
      _wsConnected = true;
      _scanError = null;
      _reconnectAttempts = 0;
      notifyListeners();
      _wsChannel!.stream.listen(_onWsMessage, onError: _onWsError, onDone: _onWsDone);
    } catch (e) {
      _wsConnected = false;
      _scanError = 'WebSocket connection failed: $e';
      notifyListeners();
      _scheduleReconnect();
    }
  }

  void _onWsMessage(dynamic raw) {
    try {
      final payload = jsonDecode(raw as String) as Map<String, dynamic>;
      final event = payload['event'] as String?;
      if (event == 'ping' || event == 'connected') return;
      if (event == 'threat_detected' ||
          event == 'flow_benign' ||
          event == 'flow_demoted') {
        _handleFlowResult(
          payload['data'] as Map<String, dynamic>,
          isThreat: event == 'threat_detected',
          isDemoted: event == 'flow_demoted',
        );
      }
    } catch (e) {
      debugPrint('WS parse error: $e');
    }
  }

  void _onWsError(dynamic error) {
    _wsConnected = false;
    _scanError = 'Live feed error — reconnecting...';
    notifyListeners();
    _scheduleReconnect();
  }

  void _onWsDone() {
    _wsConnected = false;
    notifyListeners();
    _scheduleReconnect();
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    final delaySeconds = (_baseReconnectDelay.inSeconds *
            (1 << _reconnectAttempts.clamp(0, 5)))
        .clamp(0, _maxReconnectDelay.inSeconds);
    _reconnectAttempts++;
    _reconnectTimer = Timer(Duration(seconds: delaySeconds), _connectWebSocket);
  }

  void _handleFlowResult(Map<String, dynamic> data,
      {required bool isThreat, bool isDemoted = false}) {
    final route = data['phase1_route'] as String? ??
        data['route'] as String? ??
        'UNKNOWN';
    final attackProb = (data['phase1_attack_prob'] as num?)?.toDouble() ??
        (data['attack_prob'] as num?)?.toDouble();
    final confidence = (data['phase3_confidence'] as num?)?.toDouble() ??
        (data['confidence'] as num?)?.toDouble();
    final predictedClass = data['phase3_class'] as String? ??
        data['phase2_tier'] as String? ??
        data['predicted_class'] as String?;

    // Resolve the dataset-native event time once.
    final eventTime = _parseTimestamp(data['timestamp'] as String?);

    final score = confidence ?? attackProb;
    if (score != null) {
      _confidenceScores.add(score);
      if (_confidenceScores.length > 200) _confidenceScores.removeAt(0);
    }
    final rollingAccuracy = _confidenceScores.isNotEmpty
        ? (_confidenceScores.reduce((a, b) => a + b) /
                _confidenceScores.length) *
            100
        : _stats.modelAccuracy;

    // Bucket advance is driven by event time, not wall-clock.
    _maybeAdvanceBucket(eventTime);
    if (isThreat) {
      _bucketThreats++;
    } else if (route == 'BENIGN' || isDemoted) {
      _bucketBenign++;
    } else {
      _bucketUncertain++;
    }

    if (isThreat) {
      final phase3Class = data['phase3_class'] as String? ?? '';
      final phase2Tier = data['phase2_tier'] as String? ?? '';
      final classLabel =
          phase3Class.isNotEmpty ? phase3Class : phase2Tier;

      final isNovel = data['phase3_is_novel'] as bool? ?? false;

      final isRecon = !isNovel && (classLabel == 'Portscan' || phase2Tier == 'Reconnaissance');
      final isCredAbu = !isNovel && (classLabel == 'BruteForce_HTTP' ||
          classLabel == 'BruteForce_HTTPS' ||
          phase2Tier == 'Credential_Abuse');
      // isExploit excludes novel entries — Phase 3 UNKNOWN flows that Phase 2
      // routed to Active_Exploitation must not count toward the known tier.
      final isExploit = !isNovel && (classLabel == 'SQLi_HTTP' ||
          classLabel == 'SQLi_HTTPS' ||
          phase2Tier == 'Active_Exploitation');

      final isCritical = isNovel || (attackProb != null && attackProb >= 0.90);
      _stats = _stats.copyWith(
        totalThreats: _stats.totalThreats + 1,
        criticalThreats: isCritical ? _stats.criticalThreats + 1 : _stats.criticalThreats,
        reconCount: isRecon ? _stats.reconCount + 1 : _stats.reconCount,
        credAbuseCount:
            isCredAbu ? _stats.credAbuseCount + 1 : _stats.credAbuseCount,
        exploitCount:
            isExploit ? _stats.exploitCount + 1 : _stats.exploitCount,
        novelCount:
            isNovel ? _stats.novelCount + 1 : _stats.novelCount,
        modelAccuracy: rollingAccuracy,
      );
      _notificationCount++;
    } else if (route == 'BENIGN' || isDemoted) {
      _stats = _stats.copyWith(
          benignFlows: _stats.benignFlows + 1,
          modelAccuracy: rollingAccuracy);
    } else {
      _stats = _stats.copyWith(
          uncertainFlows: _stats.uncertainFlows + 1,
          modelAccuracy: rollingAccuracy);
    }

    if (isThreat) {
      final entry = ThreatEntry.fromWsData(
          data: data,
          route: route,
          attackProb: attackProb,
          confidence: confidence,
          predictedClass: predictedClass,
          eventTime: eventTime,
          logLength: _threatCounter++);
      _threatLog.insert(0, entry);
      if (_threatLog.length > 500) _threatLog.removeLast();
      _correlateIncident(entry);
    }

    _recalculateRisk();
    notifyListeners();
  }

  static DateTime _parseTimestamp(String? raw) {
    if (raw == null) return DateTime.now();
    try {
      return DateTime.parse(raw).toLocal();
    } catch (_) {
      return DateTime.now();
    }
  }

  void _correlateIncident(ThreatEntry entry) {
    _pendingCorrelation.add(entry);
    // Use the entry's own timestamp (dataset time) for correlation windowing.
    final cutoff = entry.timestamp.subtract(_correlationWindow);
    _pendingCorrelation.removeWhere((e) => e.timestamp.isBefore(cutoff));
    _correlationTimer?.cancel();
    _correlationTimer = Timer(const Duration(seconds: 5), _flushCorrelation);
  }

  void _flushCorrelation() {
    if (_pendingCorrelation.isEmpty) return;
    final all = List<ThreatEntry>.from(_pendingCorrelation);
    _pendingCorrelation.clear();

    // ── Partition: OSR-rejected flows must never be attributed to a confirmed
    // threat technique or actor. The only reliable signal is isNovel — the
    // type field still holds the Phase-2 label (e.g. "SQLi_HTTP") for novel
    // flows because Phase 3 does not overwrite it on rejection. Grouping by
    // type before this split is what caused INC-001 to show count 12 (7
    // confirmed SQLi + 5 OSR-rejected) instead of the correct 7.
    final namedFlows = all.where((e) => !e.isNovel).toList();
    final novelFlows = all.where((e) => e.isNovel).toList();

    // ── One incident cluster per confirmed Phase-3 type ────────────────────
    // Previously this code picked only the dominant type and created a single
    // incident for all namedFlows, silently discarding every other type that
    // arrived in the same correlation window. That is why a window containing
    // 15 Portscan flows and 7 SQLi flows only ever produced one incident —
    // whichever type won the reduce() became the sole entry, and the other
    // type disappeared from the Correlated Incidents panel entirely.
    //
    // Fix: group namedFlows by type and emit one ThreatIncident per bucket.
    // Buckets sorted largest-first so INC-001 goes to the most voluminous
    // cluster, matching analyst triage expectations.
    if (namedFlows.isNotEmpty) {
      // Build per-type buckets.
      final byType = <String, List<ThreatEntry>>{};
      for (final e in namedFlows) {
        byType.putIfAbsent(e.type, () => []).add(e);
      }

      // Sort buckets by count descending.
      final sortedTypes = byType.keys.toList()
        ..sort((a, b) => byType[b]!.length.compareTo(byType[a]!.length));

      const order = ['Critical', 'High', 'Medium', 'Low'];

      for (final typeKey in sortedTypes) {
        final bucket = byType[typeKey]!;

        String topSeverity = 'Low';
        for (final e in bucket) {
          if (order.indexOf(e.severity) < order.indexOf(topSeverity)) {
            topSeverity = e.severity;
          }
        }

        final incident = ThreatIncident(
          incidentId: 'INC-${(_incidents.length + 1).toString().padLeft(3, '0')}',
          entries: bucket,
          firstSeen: bucket.last.timestamp,
          lastSeen: bucket.first.timestamp,
          dominantType: typeKey,
          severity: topSeverity,
        );
        _incidents.insert(0, incident);
        if (_incidents.length > 50) _incidents.removeLast();
      }
    }

    // ── Unclassified activity entry (OSR-rejected flows, separate entry) ──
    // Grouped under a fixed ID prefix "INC-OSR-*" so they are visually
    // distinct from numbered incident clusters in the Reports panel.
    // Even a single novel flow warrants its own entry — every OSR rejection
    // is a retraining signal.
    if (novelFlows.isNotEmpty) {
      const order = ['Critical', 'High', 'Medium', 'Low'];
      String topSeverity = 'Low';
      for (final e in novelFlows) {
        if (order.indexOf(e.severity) < order.indexOf(topSeverity)) {
          topSeverity = e.severity;
        }
      }

      // Count existing OSR incidents to give each a unique suffix.
      final osrCount = _incidents.where(
        (i) => i.incidentId.startsWith('INC-OSR'),
      ).length;
      final osrId = osrCount == 0
          ? 'INC-OSR'
          : 'INC-OSR-${(osrCount + 1).toString().padLeft(2, '0')}';

      final novelIncident = ThreatIncident(
        incidentId: osrId,
        entries: novelFlows,
        firstSeen: novelFlows.last.timestamp,
        lastSeen: novelFlows.first.timestamp,
        dominantType: 'UNKNOWN',
        severity: topSeverity,
      );
      _incidents.insert(0, novelIncident);
      if (_incidents.length > 50) _incidents.removeLast();
    }

    notifyListeners();
  }

  void _recalculateRisk() {
    double score = 0.0;
    final now = DateTime.now();
    for (final entry in _threatLog.take(100)) {
      // Decay against wall-clock so the live risk badge reflects "still
      // happening?" not "happened in 2017". This is the one place we
      // intentionally keep wall-clock semantics — replays will show the
      // last 100 entries as fresh, which is what an analyst expects of
      // a real-time risk widget.
      final ageMinutes = now.difference(entry.detectedAt).inMinutes.abs();
      final decay = 1.0 / (1.0 + ageMinutes * 0.1);
      double weight = 0.0;
      switch (entry.severity) {
        case 'Critical': weight = 40; break;
        case 'High':     weight = 20; break;
        case 'Medium':   weight = 10; break;
        default:         weight = 5;
      }
      score += weight * decay;
    }
    _riskScore = score.clamp(0.0, 100.0);
  }

  void clearNotifications() {
    _notificationCount = 0;
    notifyListeners();
  }

  void clearThreatLog() {
    _threatLog.clear();
    _incidents.clear();
    _confidenceScores.clear();
    _timeSeries.clear();
    _bucketStart = null;
    _bucketThreats = 0;
    _bucketBenign = 0;
    _bucketUncertain = 0;
    _riskScore = 0.0;
    _threatCounter = 0;
    _stats = DashboardStats.empty();
    notifyListeners();
  }

  Future<void> runScan(List<List<dynamic>> rows, String fileName) async {}

  // Removes threat log entries whose wall-clock detectedAt timestamp is older
  // than [window]. Called by Settings when the user changes log retention.
  void purgeOlderThan(Duration window) {
    final cutoff = DateTime.now().subtract(window);
    _threatLog.removeWhere((e) => e.detectedAt.isBefore(cutoff));
    notifyListeners();
  }

  Future<Map<String, dynamic>?> fetchExplanation(String flowId) =>
      _api.getExplanation(flowId);

  /// Forwarded to UI: full MITRE table for the dedicated detail page.
  Future<Map<String, dynamic>?> fetchMitreMapping() => _api.getMitreMapping();

  @override
  void dispose() {
    _wsChannel?.sink.close();
    _reconnectTimer?.cancel();
    _healthTimer?.cancel();
    _correlationTimer?.cancel();
    super.dispose();
  }
}

// ── DashboardStats ────────────────────────────────────────────────────────────
class DashboardStats {
  final int totalThreats;
  final int criticalThreats;
  final int blockedThreats;
  final int benignFlows;
  final int uncertainFlows;
  final int reconCount;
  final int credAbuseCount;
  final int exploitCount;
  final int novelCount;
  final double modelAccuracy;

  const DashboardStats({
    required this.totalThreats,
    required this.criticalThreats,
    required this.blockedThreats,
    required this.benignFlows,
    required this.uncertainFlows,
    required this.reconCount,
    required this.credAbuseCount,
    required this.exploitCount,
    required this.novelCount,
    required this.modelAccuracy,
  });

  factory DashboardStats.empty() => const DashboardStats(
        totalThreats: 0, criticalThreats: 0, blockedThreats: 0,
        benignFlows: 0, uncertainFlows: 0,
        reconCount: 0, credAbuseCount: 0, exploitCount: 0, novelCount: 0,
        modelAccuracy: 0.0,
      );

  DashboardStats copyWith({
    int? totalThreats,
    int? criticalThreats,
    int? blockedThreats,
    int? benignFlows,
    int? uncertainFlows,
    int? reconCount,
    int? credAbuseCount,
    int? exploitCount,
    int? novelCount,
    double? modelAccuracy,
  }) {
    return DashboardStats(
      totalThreats:    totalThreats    ?? this.totalThreats,
      criticalThreats: criticalThreats ?? this.criticalThreats,
      blockedThreats:  blockedThreats  ?? this.blockedThreats,
      benignFlows:     benignFlows     ?? this.benignFlows,
      uncertainFlows:  uncertainFlows  ?? this.uncertainFlows,
      reconCount:      reconCount      ?? this.reconCount,
      credAbuseCount:  credAbuseCount  ?? this.credAbuseCount,
      exploitCount:    exploitCount    ?? this.exploitCount,
      novelCount:      novelCount      ?? this.novelCount,
      modelAccuracy:   modelAccuracy   ?? this.modelAccuracy,
    );
  }
}

// ── MitreInfo (built from server-sent block; no static maps) ──────────────────
class MitreInfo {
  final String techniqueId;
  final String techniqueName;
  final String tactic;
  const MitreInfo({
    required this.techniqueId,
    required this.techniqueName,
    required this.tactic,
  });
}

// ── ThreatEntry ───────────────────────────────────────────────────────────────
class ThreatEntry {
  final String id;
  final DateTime timestamp;        // dataset-native time (shown in UI)
  final DateTime detectedAt;       // wall-clock time agent processed it (used for risk decay)
  final String type;
  final String severity;
  final String status;
  final String? originIp;
  final String? destinationIp;
  final MitreInfo? mitreInfo;
  final double? attackProbability;
  final double? modelConfidence;
  final bool isThreat;
  final bool isNovel;
  final String? recommendedAction; // server-sent NIST response
  final String? killChainPhase;    // server-sent tactic name
  final String? flowId;            // for /explain/{flow_id}

  const ThreatEntry({
    required this.id,
    required this.timestamp,
    required this.detectedAt,
    required this.type,
    required this.severity,
    required this.status,
    this.originIp,
    this.destinationIp,
    this.mitreInfo,
    this.attackProbability,
    this.modelConfidence,
    required this.isThreat,
    this.isNovel = false,
    this.recommendedAction,
    this.killChainPhase,
    this.flowId,
  });

  String get formattedTimestamp {
    final t = timestamp;
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(t.hour)}:${two(t.minute)}:${two(t.second)} '
           '${two(t.day)}/${two(t.month)}/${t.year}';
  }

  factory ThreatEntry.fromWsData({
    required Map<String, dynamic> data,
    required String route,
    required double? attackProb,
    required double? confidence,
    required String? predictedClass,
    required DateTime eventTime,
    required int logLength,
  }) {
    final id = 'TM-${(logLength + 1).toString().padLeft(4, '0')}';

    // Server has already done the MITRE lookup — just read it.
    final mitreJson = data['mitre'] as Map<String, dynamic>?;
    MitreInfo? mitre;
    if (mitreJson != null) {
      // Backend returns 'techniques' list — take the first entry as the primary technique
      final techList = (mitreJson['techniques'] as List?)?.cast<String>() ?? [];
      final tacticList = (mitreJson['tactics'] as List?)?.cast<String>() ?? [];
      final firstTech = techList.isNotEmpty ? techList.first : null;
      // Parse "T1595 (Active Scanning)" → id="T1595", name="Active Scanning"
      String techId = 'T0000';
      String techName = 'Unclassified';
      if (firstTech != null) {
        final match = RegExp(r'(T[\d.]+)\s*\(([^)]+)\)').firstMatch(firstTech);
        if (match != null) {
          techId = match.group(1)!;
          techName = match.group(2)!;
        }
      }
      mitre = MitreInfo(
        techniqueId:   mitreJson['technique_id']   as String? ?? techId,
        techniqueName: mitreJson['technique_name'] as String? ?? techName,
        tactic:        mitreJson['tactic']         as String?
                       ?? (tacticList.isNotEmpty ? tacticList.first : 'Unknown'),
      );
    }

    final isNovel = data['phase3_is_novel'] as bool? ?? false;
    final severity = isNovel
        ? 'Critical'
        : (attackProb != null || confidence != null)
            ? _severityFromProb(attackProb ?? confidence!)
            : 'Medium'; // explicitly unknown — no probability available

    // For OSR-rejected flows, phase3_class is null (the classifier produced no
    // confirmed label).  Falling through to predictedClass / route would give
    // the Phase-2 tier string (e.g. "Active_Exploitation" or "SQLi_HTTP"),
    // which is what caused the incident-label bug: novel flows carried the same
    // type as the confirmed SQLi flows and were grouped with them.
    // Force type to 'UNKNOWN' so no type-based grouping can misattribute them.
    final phase3Class = data['phase3_class'] as String?;
    final type = isNovel ? 'UNKNOWN' : (phase3Class ?? predictedClass ?? route);

    return ThreatEntry(
      id: id,
      timestamp: eventTime,
      detectedAt: DateTime.now(),   // wall-clock — used for risk score decay
      type: type,
      severity: severity,
      status: 'Active',
      originIp: data['src_ip'] as String?,
      destinationIp: data['dst_ip'] as String?,
      mitreInfo: mitre,
      attackProbability: attackProb,
      modelConfidence: confidence,
      isThreat: true,
      isNovel: isNovel,
      // NIST response from server is the recommended action.
      recommendedAction: mitreJson?['nist_response'] as String? ??
          'Flag for analyst review',
      // Tactic name is the kill-chain phase.
      killChainPhase: mitreJson?['tactic'] as String? ?? 'Unknown',
      flowId: data['flow_id'] as String?,
    );
  }

  static String _severityFromProb(double prob) {
    if (prob >= 0.90) return 'Critical';
    if (prob >= 0.75) return 'High';
    if (prob >= 0.50) return 'Medium';
    return 'Low';
  }
}