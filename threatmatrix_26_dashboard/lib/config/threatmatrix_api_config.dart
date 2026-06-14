// lib/config/threatmatrix_api_config.dart
//
// Single source of truth for the FastAPI backend's base URL.
// All HTTP and WebSocket calls in the dashboard MUST go through this class.
//
// Resolution order (first match wins):
//   1. --dart-define=API_BASE_URL=...    (production builds)
//   2. Default localhost (kDebugMode only — release builds REFUSE to fall
//      back to localhost; this prevents shipping a debug URL by accident).
//
// Build examples
// --------------
// Local development against docker-compose ml-service (HTTP first):
//   flutter run -d chrome --dart-define=API_BASE_URL=http://localhost:8000
//
// Local development against the local Caddy HTTPS profile:
//   flutter run -d chrome --dart-define=API_BASE_URL=https://localhost
//
// Production (Cloudflare Tunnel / Railway custom domain):
//   flutter build web --release \
//     --dart-define=API_BASE_URL=https://api.yourdomain.com

import 'package:flutter/foundation.dart';

class ApiConfig {
  static const String _envBaseUrl =
      String.fromEnvironment('API_BASE_URL', defaultValue: '');

  static String? _runtimeAuthToken;

  /// Set after a successful Auth0 / Supabase login. Will be appended to the
  /// WebSocket URL as ?token=... so the FastAPI handshake can validate it.
  static void setAuthToken(String? token) {
    _runtimeAuthToken = token;
  }

  static String? get authToken => _runtimeAuthToken;

  /// HTTP/HTTPS base URL of the FastAPI service.
  /// Throws in release builds if no API_BASE_URL was supplied at build time —
  /// shipping a release build with a debug URL would be a deployment incident.
  static String get baseUrl {
    if (_envBaseUrl.isNotEmpty) return _stripTrailingSlash(_envBaseUrl);
    if (kReleaseMode) {
      throw StateError(
        'ApiConfig: API_BASE_URL was not provided at build time.\n'
        'Release builds must be invoked with '
        '--dart-define=API_BASE_URL=https://api.yourdomain.com',
      );
    }
    return 'http://localhost:8000';
  }

  /// WebSocket URL. http→ws, https→wss. Auth token (if any) appended as
  /// ?token=... query parameter so browsers (which can't set Authorization
  /// headers on WS upgrades) can still authenticate.
  static String get webSocketUrl {
    final uri = Uri.parse(baseUrl);
    final wsScheme = (uri.scheme == 'https') ? 'wss' : 'ws';
    final wsUri = uri.replace(scheme: wsScheme, path: '/ws/threats');
    if (_runtimeAuthToken != null && _runtimeAuthToken!.isNotEmpty) {
      return wsUri.replace(queryParameters: {
        'token': _runtimeAuthToken!,
      }).toString();
    }
    return wsUri.toString();
  }

  static bool get isSecure => Uri.parse(baseUrl).scheme == 'https';

  // Endpoint convenience getters.
  static String get healthUrl  => '$baseUrl/health';
  static String get metricsUrl => '$baseUrl/metrics';
  static String get predictUrl => '$baseUrl/predict';
  static String get ingestUrl  => '$baseUrl/ingest';
  static String get mitreUrl   => '$baseUrl/mitre';
  static String explainUrl(String flowId) => '$baseUrl/explain/$flowId';

  static String _stripTrailingSlash(String url) =>
      url.endsWith('/') ? url.substring(0, url.length - 1) : url;
}