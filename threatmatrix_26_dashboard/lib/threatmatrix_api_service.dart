// ThreatMatrix API Service
// Connects Flutter dashboard to the Dockerised ML inference service.

import 'dart:convert';
import 'package:http/http.dart' as http;

import 'config/threatmatrix_api_config.dart';

// ─── Server-sent MITRE block ─────────────────────────────────────────────────
class ServerMitreInfo {
  final String? techniqueId;
  final String? techniqueName;
  final String? tactic;
  final String? tacticId;
  final List<String> techniques;
  final List<String> tactics;
  final List<String> mitigations;
  final List<String> urls;
  final String? nistSeverity;
  final String? nistResponse;

  const ServerMitreInfo({
    this.techniqueId,
    this.techniqueName,
    this.tactic,
    this.tacticId,
    this.techniques = const [],
    this.tactics = const [],
    this.mitigations = const [],
    this.urls = const [],
    this.nistSeverity,
    this.nistResponse,
  });

  factory ServerMitreInfo.fromJson(Map<String, dynamic> j) {
    return ServerMitreInfo(
      techniqueId:   j['technique_id']   as String?,
      techniqueName: j['technique_name'] as String?,
      tactic:        j['tactic']         as String?,
      tacticId:      j['tactic_id']      as String?,
      techniques:    (j['techniques']  as List?)?.cast<String>() ?? const [],
      tactics:       (j['tactics']     as List?)?.cast<String>() ?? const [],
      mitigations:   (j['mitigations'] as List?)?.cast<String>() ?? const [],
      urls:          (j['urls']        as List?)?.cast<String>() ?? const [],
      nistSeverity:  j['nist_severity'] as String?,
      nistResponse:  j['nist_response'] as String?,
    );
  }
}

// ─── Data Models ─────────────────────────────────────────────────────────────

class NetworkFlow {
  final String? srcIp;
  final String? dstIp;

  // 16-feature ML vector (matches UNIVERSAL_FEATURES in threatmatrix_binary.py)
  final double flowDuration;
  final double fwdPktsTot;
  final double bwdPktsTot;
  final double fwdDataPktsTot;
  final double bwdDataPktsTot;
  final double flowPktsPerSec;
  final double fwdPktsPerSec;
  final double bwdPktsPerSec;
  final double payloadBytesPerSecond;
  final double downUpRatio;
  final double fwdHeaderSizeTot;
  final double bwdHeaderSizeTot;
  final double flowFinFlagCount;
  final double flowSynFlagCount;
  final double flowRstFlagCount;
  final double flowAckFlagCount;

  const NetworkFlow({
    this.srcIp,
    this.dstIp,
    required this.flowDuration,
    required this.fwdPktsTot,
    required this.bwdPktsTot,
    this.fwdDataPktsTot = 0.0,
    this.bwdDataPktsTot = 0.0,
    required this.flowPktsPerSec,
    required this.fwdPktsPerSec,
    required this.bwdPktsPerSec,
    required this.payloadBytesPerSecond,
    required this.downUpRatio,
    this.fwdHeaderSizeTot = 0.0,
    this.bwdHeaderSizeTot = 0.0,
    required this.flowFinFlagCount,
    required this.flowSynFlagCount,
    required this.flowRstFlagCount,
    required this.flowAckFlagCount,
  });

  Map<String, dynamic> toJson() => {
        if (srcIp != null) 'src_ip': srcIp,
        if (dstIp != null) 'dst_ip': dstIp,
        'flow_duration': flowDuration,
        'fwd_pkts_tot': fwdPktsTot,
        'bwd_pkts_tot': bwdPktsTot,
        'fwd_data_pkts_tot': fwdDataPktsTot,
        'bwd_data_pkts_tot': bwdDataPktsTot,
        'flow_pkts_per_sec': flowPktsPerSec,
        'fwd_pkts_per_sec': fwdPktsPerSec,
        'bwd_pkts_per_sec': bwdPktsPerSec,
        'payload_bytes_per_second': payloadBytesPerSecond,
        'down_up_ratio': downUpRatio,
        'fwd_header_size_tot': fwdHeaderSizeTot,
        'bwd_header_size_tot': bwdHeaderSizeTot,
        'flow_FIN_flag_count': flowFinFlagCount,
        'flow_SYN_flag_count': flowSynFlagCount,
        'flow_RST_flag_count': flowRstFlagCount,
        'flow_ACK_flag_count': flowAckFlagCount,
      };
}

class ThreatPrediction {
  final String route;
  final String? srcIp;
  final String? dstIp;
  final double? attackProb;
  final String? predictedClass;
  final double? confidence;
  final String phase1Route;
  final String? phase2Result;
  final String? phase3Class;
  final double? phase3Confidence;
  final double? phase3OodScore;
  final bool phase3IsNovel;
  final ServerMitreInfo? mitreInfo;
  final DateTime timestamp;
  final DateTime detectedAt;

  ThreatPrediction({
    required this.route,
    this.srcIp,
    this.dstIp,
    this.attackProb,
    this.predictedClass,
    this.confidence,
    required this.phase1Route,
    this.phase2Result,
    this.phase3Class,
    this.phase3Confidence,
    this.phase3OodScore,
    this.phase3IsNovel = false,
    this.mitreInfo,
    DateTime? timestamp,
    DateTime? detectedAt,
  })  : timestamp = timestamp ?? DateTime.now(),
        detectedAt = detectedAt ?? DateTime.now();

  factory ThreatPrediction.fromJson(Map<String, dynamic> json) {
    DateTime parseTs(String? raw) {
      if (raw == null) return DateTime.now();
      try {
        return DateTime.parse(raw).toLocal();
      } catch (_) {
        return DateTime.now();
      }
    }

    final mitreJson = json['mitre'] as Map<String, dynamic>?;

    return ThreatPrediction(
      route: json['phase1_route'] as String? ??
          json['route'] as String? ??
          'UNKNOWN',
      srcIp: json['src_ip'] as String?,
      dstIp: json['dst_ip'] as String?,
      attackProb: (json['phase1_attack_prob'] as num?)?.toDouble() ??
          (json['attack_prob'] as num?)?.toDouble(),
      predictedClass: json['phase3_class'] as String? ??
          json['predicted_class'] as String?,
      confidence: (json['phase3_confidence'] as num?)?.toDouble() ??
          (json['confidence'] as num?)?.toDouble(),
      phase1Route: json['phase1_route'] as String? ?? '',
      phase2Result: json['phase2_tier'] as String?,
      phase3Class: json['phase3_class'] as String?,
      phase3Confidence: (json['phase3_confidence'] as num?)?.toDouble(),
      phase3OodScore: (json['phase3_ood_score'] as num?)?.toDouble(),
      phase3IsNovel: json['phase3_is_novel'] as bool? ?? false,
      mitreInfo: mitreJson != null ? ServerMitreInfo.fromJson(mitreJson) : null,
      timestamp:  parseTs(json['timestamp']   as String?),
      detectedAt: parseTs(json['detected_at'] as String?),
    );
  }

  bool get isThreat    => route != 'BENIGN';
  bool get isUncertain => route.contains('UNCERTAIN');
  bool get isNovel     => phase3IsNovel;

  String get severityLabel {
    if (!isThreat) return 'Low';
    if (phase3IsNovel) return 'Critical';
    if (attackProb == null) return 'Medium';
    if (attackProb! >= 0.90) return 'Critical';
    if (attackProb! >= 0.70) return 'High';
    return 'Medium';
  }
}

// ─── HealthStatus ─────────────────────────────────────────────────────────────

class HealthStatus {
  final bool isOnline;
  final bool phase1Ready;
  final bool phase2Ready;
  final bool phase3Ready;
  final int? wsClients;
  final int? flowBuffer;

  const HealthStatus({
    required this.isOnline,
    required this.phase1Ready,
    required this.phase2Ready,
    this.phase3Ready = false,
    this.wsClients,
    this.flowBuffer,
  });

  factory HealthStatus.unknown() => const HealthStatus(
        isOnline: false, phase1Ready: false, phase2Ready: false,
      );

  factory HealthStatus.offline() => const HealthStatus(
        isOnline: false, phase1Ready: false, phase2Ready: false,
      );
}

// ─── PhaseMetrics — certified metrics for a single pipeline phase ─────────────

class PhaseMetrics {
  final String label;
  final String description;
  final double? accuracy;
  final double? precision;
  final double? recall;
  final double? f1Score;
  final double? rocAuc;
  final double? prAuc;
  final String? note;

  const PhaseMetrics({
    required this.label,
    this.description = '',
    this.accuracy,
    this.precision,
    this.recall,
    this.f1Score,
    this.rocAuc,
    this.prAuc,
    this.note,
  });

  factory PhaseMetrics.fromJson(Map<String, dynamic> j) => PhaseMetrics(
        label:       j['label']       as String? ?? '',
        description: j['description'] as String? ?? '',
        accuracy:    (j['accuracy']   as num?)?.toDouble(),
        precision:   (j['precision']  as num?)?.toDouble(),
        recall:      (j['recall']     as num?)?.toDouble(),
        f1Score:     (j['f1_score']   as num?)?.toDouble(),
        rocAuc:      (j['roc_auc']    as num?)?.toDouble(),
        prAuc:       (j['pr_auc']     as num?)?.toDouble(),
        note:        j['note']        as String?,
      );
}

// MultiPhaseMetrics — container for all three phase metrics 

class MultiPhaseMetrics {
  final PhaseMetrics phase1;
  final PhaseMetrics phase2;
  final PhaseMetrics phase3;
  final String evaluatedOn;
  final bool isLoading;

  const MultiPhaseMetrics({
    required this.phase1,
    required this.phase2,
    required this.phase3,
    this.evaluatedOn = '',
    this.isLoading = false,
  });

  factory MultiPhaseMetrics.loading() => const MultiPhaseMetrics(
        phase1: PhaseMetrics(label: ''),
        phase2: PhaseMetrics(label: ''),
        phase3: PhaseMetrics(label: ''),
        isLoading: true,
      );

  factory MultiPhaseMetrics.unavailable() => const MultiPhaseMetrics(
        phase1: PhaseMetrics(label: 'Phase 1 — Binary Detection'),
        phase2: PhaseMetrics(label: 'Phase 2 — Severity Router'),
        phase3: PhaseMetrics(label: 'Phase 3 — RF + OSR'),
        isLoading: false,
      );

  factory MultiPhaseMetrics.fromJson(Map<String, dynamic> j) {
    // New multi-phase format from updated metrics.json
    if (j.containsKey('phase_1')) {
      return MultiPhaseMetrics(
        phase1:      PhaseMetrics.fromJson(j['phase_1'] as Map<String, dynamic>),
        phase2:      PhaseMetrics.fromJson(j['phase_2'] as Map<String, dynamic>),
        phase3:      PhaseMetrics.fromJson(j['phase_3'] as Map<String, dynamic>),
        evaluatedOn: j['evaluated_on'] as String? ?? '',
        isLoading:   false,
      );
    }
    // Graceful fallback: old flat format — slots into Phase 1 only
    final flat = PhaseMetrics(
      label:     j['evaluated_on'] as String? ?? 'Phase 1',
      accuracy:  (j['accuracy']  as num?)?.toDouble(),
      precision: (j['precision'] as num?)?.toDouble(),
      recall:    (j['recall']    as num?)?.toDouble(),
      f1Score:   (j['f1_score']  as num?)?.toDouble(),
    );
    return MultiPhaseMetrics(
      phase1:      flat,
      phase2:      const PhaseMetrics(label: 'Phase 2 — Severity Router'),
      phase3:      const PhaseMetrics(label: 'Phase 3 — RF + OSR'),
      evaluatedOn: j['evaluated_on'] as String? ?? '',
      isLoading:   false,
    );
  }

  // Convenience getters — keep existing callers (provider, reports) working
  double? get accuracy  => phase1.accuracy;
  double? get precision => phase1.precision;
  double? get recall    => phase1.recall;
  double? get f1Score   => phase1.f1Score;
}

// Typedef alias — no other file needs to change its ModelMetrics references
typedef ModelMetrics = MultiPhaseMetrics;

// ─── API Service ─────────────────────────────────────────────────────────────

class ThreatMatrixApiService {
  final Duration timeout;

  ThreatMatrixApiService({this.timeout = const Duration(seconds: 10)});

  String get baseUrl => ApiConfig.baseUrl;

  Map<String, String> _headers({bool json = false}) {
    final h = <String, String>{};
    if (json) h['Content-Type'] = 'application/json';
    final token = ApiConfig.authToken;
    if (token != null && token.isNotEmpty) {
      h['Authorization'] = 'Bearer $token';
    }
    return h;
  }

  Future<ModelMetrics> getMetrics() async {
    try {
      final response = await http
          .get(Uri.parse(ApiConfig.metricsUrl), headers: _headers())
          .timeout(timeout);
      if (response.statusCode == 200) {
        final json = jsonDecode(response.body) as Map<String, dynamic>;
        return ModelMetrics.fromJson(json);
      }
      return ModelMetrics.unavailable();
    } catch (_) {
      return ModelMetrics.unavailable();
    }
  }

  Future<HealthStatus> getHealth() async {
    try {
      final response = await http
          .get(Uri.parse(ApiConfig.healthUrl), headers: _headers())
          .timeout(timeout);

      if (response.statusCode == 200) {
        final json = jsonDecode(response.body) as Map<String, dynamic>;
        return HealthStatus(
          isOnline:    true,
          phase1Ready: json['phase1_ready'] as bool? ?? false,
          phase2Ready: json['phase2_ready'] as bool? ?? false,
          phase3Ready: json['phase3_ready'] as bool? ?? false,
          wsClients:   (json['ws_clients']  as num?)?.toInt(),
          flowBuffer:  (json['flow_buffer'] as num?)?.toInt(),
        );
      }
      return HealthStatus.offline();
    } catch (_) {
      return HealthStatus.offline();
    }
  }

  Future<List<ThreatPrediction>> predict(List<NetworkFlow> flows) async {
    final body = jsonEncode({
      'flows': flows.map((f) => f.toJson()).toList(),
    });

    final response = await http
        .post(
          Uri.parse(ApiConfig.predictUrl),
          headers: _headers(json: true),
          body: body,
        )
        .timeout(timeout);

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      return (json['predictions'] as List)
          .map((p) => ThreatPrediction.fromJson(p as Map<String, dynamic>))
          .toList();
    }

    throw Exception(
        'Prediction failed: ${response.statusCode} — ${response.body}');
  }

  Future<Map<String, dynamic>?> getExplanation(String flowId) async {
    try {
      final response = await http
          .get(Uri.parse(ApiConfig.explainUrl(flowId)), headers: _headers())
          .timeout(const Duration(seconds: 30));
      if (response.statusCode == 200) {
        return jsonDecode(response.body) as Map<String, dynamic>;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// GET /mitre — full MITRE ATT&CK + NIST mapping from the backend.
  /// The MITRE detail page fetches this at mount time. The dashboard does
  /// not keep its own copy — single source of truth is the Python mapping file.
  Future<Map<String, dynamic>?> getMitreMapping() async {
    try {
      final response = await http
          .get(Uri.parse(ApiConfig.mitreUrl), headers: _headers())
          .timeout(timeout);
      if (response.statusCode == 200) {
        return jsonDecode(response.body) as Map<String, dynamic>;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// POST /config — update the Phase 1 alert sensitivity threshold at runtime.
  /// [value] maps to low_conf_max in EnsembleModel (range 0.01–0.50).
  /// Returns true if the backend accepted the change, false on any error.
  Future<bool> setAlertThreshold(double value) async {
    try {
      final response = await http
          .post(
            Uri.parse('$baseUrl/config'),
            headers: _headers(json: true),
            body: jsonEncode({'low_conf_max': value}),
          )
          .timeout(timeout);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  static List<NetworkFlow> parseCsvRows(List<List<dynamic>> rows) {
    final flows = <NetworkFlow>[];
    for (final row in rows) {
      if (row.length < 12) continue;
      try {
        flows.add(NetworkFlow(
          flowDuration:          double.parse(row[0].toString()),
          fwdPktsTot:            double.parse(row[1].toString()),
          bwdPktsTot:            double.parse(row[2].toString()),
          payloadBytesPerSecond: double.parse(row[3].toString()),
          flowPktsPerSec:        double.parse(row[4].toString()),
          fwdPktsPerSec:         double.parse(row[5].toString()),
          bwdPktsPerSec:         double.parse(row[6].toString()),
          downUpRatio:           double.parse(row[7].toString()),
          flowFinFlagCount:      double.parse(row[8].toString()),
          flowSynFlagCount:      double.parse(row[9].toString()),
          flowRstFlagCount:      double.parse(row[10].toString()),
          flowAckFlagCount:      double.parse(row[11].toString()),
        ));
      } catch (_) {
        continue;
      }
    }
    return flows;
  }
}