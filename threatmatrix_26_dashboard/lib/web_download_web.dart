// web_download_web.dart
// Used ONLY on Flutter Web builds.
// The conditional import in reports_page.dart picks this file automatically.
//
// ignore: deprecated_member_use, avoid_web_libraries_in_flutter
import 'dart:html' as html;

void triggerWebDownload(String filename, String content) {
  final blob = html.Blob([content], 'text/plain', 'native');
  final url  = html.Url.createObjectUrlFromBlob(blob);
  html.AnchorElement(href: url)
    ..setAttribute('download', filename)
    ..click();
  html.Url.revokeObjectUrl(url);
}