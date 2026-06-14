// web_download_stub.dart
// Used on native (Android, iOS, Windows, macOS, Linux) platforms.
// The conditional import in reports_page.dart picks this file on non-web builds.
void triggerWebDownload(String filename, String content) {
  throw UnsupportedError('triggerWebDownload is only supported on Flutter Web.');
}