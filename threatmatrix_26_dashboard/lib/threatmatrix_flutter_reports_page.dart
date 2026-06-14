// threatmatrix_flutter_reports_page.dart
// This file implements the "Reports" page of the ThreatMatrix.


import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart'
    show kIsWeb, defaultTargetPlatform, TargetPlatform;
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';

// PDF + Printing packages
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

import 'web_download_stub.dart'
    if (dart.library.html) 'web_download_web.dart';

import 'threatmatrix_flutter_theme_provider.dart';
import 'threatmatrix_provider.dart';

// ─── Helper: convert PdfColor + white blend to a light opaque background ─────
// alpha=0.07 blended with white → PdfColor( r*0.07+0.93, g*0.07+0.93, b*0.07+0.93 )
PdfColor _lightBg(PdfColor c, [double strength = 0.10]) {
  return PdfColor(
    c.red * strength + (1 - strength),
    c.green * strength + (1 - strength),
    c.blue * strength + (1 - strength),
  );
}

PdfColor _lightBorder(PdfColor c, [double strength = 0.35]) {
  return PdfColor(
    c.red * strength + (1 - strength),
    c.green * strength + (1 - strength),
    c.blue * strength + (1 - strength),
  );
}

class ReportsPage extends StatefulWidget {
  final bool isDarkMode;
  const ReportsPage({super.key, required this.isDarkMode});

  @override
  State<ReportsPage> createState() => _ReportsPageState();
}

class _ReportsPageState extends State<ReportsPage> {
  String _selectedFormat = 'PDF';
  bool _isGenerating = false;
  final List<_ReportHistoryEntry> _reportHistory = [];

  final List<({String label, IconData icon})> _formats = [
    (label: 'PDF', icon: Icons.picture_as_pdf_outlined),
    (label: 'CSV', icon: Icons.table_chart_outlined),
    (label: 'JSON', icon: Icons.data_object_outlined),
  ];

  // ──────────────────────────────────────────────────────────────────────────
  // Modern popup dialog — replaces SnackBar for all action feedback
  // ──────────────────────────────────────────────────────────────────────────

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
          width: 420,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(32, 32, 32, 28),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
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
                      fontSize: 17, fontWeight: FontWeight.bold,
                      color: tp.getTextColor(), fontFamily: 'Courier Prime'),
                  textAlign: TextAlign.center),
              const SizedBox(height: 10),
              Text(message,
                  style: TextStyle(
                      fontSize: 13, color: tp.getTextSecondaryColor(), height: 1.5),
                  textAlign: TextAlign.center),
              const SizedBox(height: 28),
              Divider(color: tp.getBorderColor(), height: 1),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: () => Navigator.pop(context),
                style: ElevatedButton.styleFrom(
                  backgroundColor: color,
                  foregroundColor: tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                  minimumSize: const Size(140, 42),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
                child: const Text('OK', style: TextStyle(fontWeight: FontWeight.w600)),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Build
  // ──────────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Consumer<ThemeProvider>(
      builder: (_, tp, __) => Consumer<ThreatMatrixProvider>(
        builder: (_, provider, __) => SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child:
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _buildReportPreview(tp, provider),
              const SizedBox(height: 24),
              _buildReportHistory(tp),
            ]),
          ),
        ),
      ),
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Report History
  // ──────────────────────────────────────────────────────────────────────────

  Widget _buildReportHistory(ThemeProvider tp) {
    return Container(
      decoration: BoxDecoration(
          color: tp.getCardColor(),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: tp.getBorderColor())),
      child: Column(children: [
        // Header
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          child:
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Row(children: [
              Container(
                  width: 4,
                  height: 18,
                  decoration: BoxDecoration(
                      color: tp.getSuccessColor(),
                      borderRadius: BorderRadius.circular(2))),
              const SizedBox(width: 10),
              Text('Generated Reports',
                  style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: tp.getTextColor(),
                      fontFamily: 'Courier Prime')),
              const SizedBox(width: 10),
              if (_reportHistory.isNotEmpty)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                      color: tp.getSuccessColor().withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(10)),
                  child: Text('${_reportHistory.length}',
                      style: TextStyle(
                          fontSize: 11,
                          color: tp.getSuccessColor(),
                          fontWeight: FontWeight.w600)),
                ),
            ]),
            Text('Last 10 reports',
                style: TextStyle(fontSize: 12, color: tp.getTextMutedColor())),
          ]),
        ),
        Divider(color: tp.getBorderColor(), height: 1),

        // Table header
        Container(
          color: tp.isDarkMode
              ? const Color(0xFF111318).withValues(alpha: 0.5)
              : const Color(0xFFF5F5F5),
          child: Padding(
            padding:
                const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
            child: Row(children: [
              Expanded(flex: 5, child: _th('Report Name', tp, center: false)),
              Expanded(flex: 3, child: _th('Generated', tp)),
              Expanded(flex: 2, child: _th('Period', tp)),
              Expanded(flex: 2, child: _th('Format', tp)),
              Expanded(flex: 2, child: _th('Threats', tp)),
              Expanded(flex: 3, child: _th('Actions', tp)),
            ]),
          ),
        ),
        Divider(color: tp.getBorderColor(), height: 1),

        // Rows
        if (_reportHistory.isEmpty)
          Padding(
            padding: const EdgeInsets.all(28),
            child: Center(
                child: Column(children: [
              Icon(Icons.description_outlined,
                  color: tp.getTextMutedColor().withValues(alpha: 0.35),
                  size: 36),
              const SizedBox(height: 8),
              Text('No reports generated yet',
                  style:
                      TextStyle(fontSize: 13, color: tp.getTextMutedColor())),
              const SizedBox(height: 4),
              Text('Generate your first report using the form above',
                  style: TextStyle(
                      fontSize: 12,
                      color: tp.getTextMutedColor().withValues(alpha: 0.6))),
            ])),
          )
        else
          ..._reportHistory.asMap().entries.map((e) {
            final entry = e.value;
            final isEven = e.key % 2 == 0;
            final formatColor = entry.format == 'PDF'
                ? tp.getDangerColor()
                : entry.format == 'CSV'
                    ? const Color(0xFF1B5E20)
                    : (tp.isDarkMode
                        ? const Color(0xFF42A5F5)
                        : const Color(0xFF1565C0));
            final formatIcon = entry.format == 'PDF'
                ? Icons.picture_as_pdf_outlined
                : entry.format == 'CSV'
                    ? Icons.table_chart_outlined
                    : Icons.data_object_outlined;


            return Container(
              decoration: BoxDecoration(
                color: isEven
                    ? Colors.transparent
                    : (tp.isDarkMode
                        ? Colors.white.withValues(alpha: 0.02)
                        : Colors.black.withValues(alpha: 0.015)),
                border: Border(
                    bottom:
                        BorderSide(color: tp.getBorderColor(), width: 1)),
              ),
              child: Padding(
                padding: const EdgeInsets.symmetric(
                    horizontal: 24, vertical: 11),
                child: Row(children: [
                  Expanded(
                      flex: 5,
                      child: Row(children: [
                        Icon(formatIcon, size: 14, color: formatColor),
                        const SizedBox(width: 8),
                        Expanded(
                            child: Text(entry.filename,
                                style: TextStyle(
                                    fontSize: 12,
                                    color: tp.getTextColor(),
                                    fontFamily: 'Courier Prime'),
                                overflow: TextOverflow.ellipsis)),
                      ])),
                  Expanded(
                      flex: 3,
                      child: Text(_formatDate(entry.generatedAt),
                          textAlign: TextAlign.center,
                          style: TextStyle(
                              fontSize: 12,
                              color: tp.getTextSecondaryColor()))),
                  Expanded(
                      flex: 2,
                      child: Text(entry.period,
                          textAlign: TextAlign.center,
                          style: TextStyle(
                              fontSize: 12,
                              color: tp.getTextSecondaryColor()))),
                  Expanded(
                      flex: 2,
                      child: Center(
                        child: _compactPill(entry.format, formatColor),
                      )),
                  Expanded(
                      flex: 2,
                      child: Text(
                        entry.threatCount.toString(),
                        textAlign: TextAlign.center,
                        style: TextStyle(
                            fontSize: 12,
                            color: entry.threatCount > 0
                                ? tp.getDangerColor()
                                : tp.getTextMutedColor(),
                            fontFamily: 'Courier Prime',
                            fontWeight: FontWeight.w600),
                      )),
                  Expanded(
                      flex: 3,
                      child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                        _actionIconBtn(
                            icon: Icons.download_outlined,
                            color: tp.getSuccessColor(),
                            tooltip: 'Download',
                            onTap: () async {
                              if (kIsWeb) {
                                await _showResultDialog(
                                  Provider.of<ThemeProvider>(context, listen: false),
                                  success: false,
                                  title: 'Re-export Required',
                                  message: 'Web downloads cannot be re-triggered from history. '
                                      'Use "Export & Save" above to generate and download the report again.',
                                  icon: Icons.info_outline_rounded,
                                );
                              } else {
                                await _openFile(entry.savedPath);
                              }
                            }),
                        const SizedBox(width: 6),
                        _actionIconBtn(
                            icon: Icons.delete_outline_rounded,
                            color: tp.getDangerColor(),
                            tooltip: 'Remove from history',
                            onTap: () async {
                              final ok = await _showReportConfirmDialog(
                                context: context,
                                tp: tp,
                                title: 'Remove Report',
                                message: 'Remove "${entry.filename}" from history? The saved file will not be deleted.',
                              );
                              if (ok) {
                                setState(() => _reportHistory.removeWhere(
                                    (r) => r.filename == entry.filename));
                              }
                            }),
                      ])),
                ]),
              ),
            );
          }),
      ]),
    );
  }

  Widget _actionIconBtn(
      {required IconData icon,
      required Color color,
      required String tooltip,
      required VoidCallback onTap}) {
    return _TmIconButton(icon: icon, color: color, tooltip: tooltip, onTap: onTap);
  }

  Future<void> _openFile(String path) async {
    try {
      if (defaultTargetPlatform == TargetPlatform.windows) {
        await Process.run('cmd', ['/c', 'start', '', path]);
      } else if (defaultTargetPlatform == TargetPlatform.macOS) {
        await Process.run('open', [path]);
      } else if (defaultTargetPlatform == TargetPlatform.linux) {
        await Process.run('xdg-open', [path]);
      }
    } catch (_) {}
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Generate Report
  // ──────────────────────────────────────────────────────────────────────────

  Future<void> _generateReport(
      ThreatMatrixProvider provider, ThemeProvider tp) async {
    final now = DateTime.now();
    final ts =
        '${now.year}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}_${now.hour.toString().padLeft(2, '0')}${now.minute.toString().padLeft(2, '0')}${now.second.toString().padLeft(2, '0')}';

    // ── PDF ───────────────────────────────────────────────────────────────
    if (_selectedFormat == 'PDF') {
      setState(() {
        _isGenerating = true;
      });
      // Allow the frame to fully rebuild before opening the print dialog,
      // which prevents the first-time blank preview issue.
      await Future.delayed(const Duration(milliseconds: 80));
      try {
        final filename = 'ThreatMatrix_ThreatAnalysis_$ts.pdf';
        await _exportPdf(provider, filename, now);
        if (mounted) {
          setState(() {
            _reportHistory.insert(
                0,
                _ReportHistoryEntry(
                    filename: filename,
                    savedPath: filename,
                    format: 'PDF',
                    period: 'All Available Data',
                    generatedAt: now,
                    threatCount: provider.threatLog.length));
            if (_reportHistory.length > 10) _reportHistory.removeLast();
          });
          await _showResultDialog(
            tp,
            success: true,
            title: 'PDF Exported',
            message: 'Your report has been sent to the print / save dialog. '
                'Use the dialog to save or print the PDF.',
            icon: Icons.picture_as_pdf_rounded,
          );
        }
      } catch (e) {
        if (mounted) {
          await _showResultDialog(tp,
              success: false,
              title: 'Export Failed',
              message: 'PDF export encountered an error:\n$e');
        }
      } finally {
        if (mounted) setState(() => _isGenerating = false);
      }
      return;
    }

    // ── CSV / JSON ────────────────────────────────────────────────────────
    final ext = switch (_selectedFormat) {
      'CSV' => 'csv',
      'JSON' => 'json',
      _ => 'txt',
    };

    final filename = 'ThreatMatrix_ThreatAnalysis_$ts.$ext';
    final content = switch (_selectedFormat) {
      'JSON' => const JsonEncoder.withIndent('  ')
          .convert(_buildReportJson(provider)),
      'CSV' => _buildCsv(provider.threatLog),
      _ => _buildPlainTextReport(provider),
    };

    if (!mounted) return;
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (_) => _PreviewDialog(
          filename: filename,
          content: content,
          format: _selectedFormat,
          tp: tp),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _isGenerating = true;
    });

    try {
      if (kIsWeb) {
        triggerWebDownload(filename, content);
        if (mounted) {
          setState(() {
            _reportHistory.insert(
                0,
                _ReportHistoryEntry(
                    filename: filename,
                    savedPath: filename,
                    format: _selectedFormat,
                    period: 'All Available Data',
                    generatedAt: now,
                    threatCount: provider.threatLog.length));
            if (_reportHistory.length > 10) _reportHistory.removeLast();
          });
          await _showResultDialog(tp,
              success: true,
              title: 'Report Downloaded',
              message: 'Your report "$filename" has been sent to your browser\'s Downloads folder.',
              icon: Icons.download_done_rounded);
        }
      } else {
        final savePath = await _getSavePath();
        final file = File('$savePath/$filename');
        await file.writeAsString(content, encoding: utf8);
        if (mounted) {
          setState(() {
            _reportHistory.insert(
                0,
                _ReportHistoryEntry(
                    filename: filename,
                    savedPath: file.path,
                    format: _selectedFormat,
                    period: 'All Available Data',
                    generatedAt: now,
                    threatCount: provider.threatLog.length));
            if (_reportHistory.length > 10) _reportHistory.removeLast();
          });
          await _showResultDialog(tp,
              success: true,
              title: 'Report Saved',
              message: 'Your report has been saved to:\n${file.path}',
              icon: Icons.save_alt_rounded);
        }
      }
    } catch (e) {
      if (mounted) {
        await _showResultDialog(tp,
            success: false,
            title: 'Save Failed',
            message: 'Could not write report to disk:\n$e\n\n'
                'Check that the Downloads folder exists and is writable.');
      }
    } finally {
      if (mounted) setState(() => _isGenerating = false);
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PDF Builder
  // ──────────────────────────────────────────────────────────────────────────

  Future<void> _exportPdf(
      ThreatMatrixProvider provider, String filename, DateTime now) async {
    // FIX-E: Load embedded Unicode fonts so text is selectable/copy-pasteable
    final fontRegular = await PdfGoogleFonts.notoSansRegular();
    final fontBold = await PdfGoogleFonts.notoSansBold();
    final fontItalic = await PdfGoogleFonts.notoSansItalic();
    final fontMono = await PdfGoogleFonts.notoSansMonoRegular();
    final fontMonoBold = await PdfGoogleFonts.notoSansMonoBold();

    final stats = provider.stats;
    final log = provider.threatLog;
    final total =
        stats.totalThreats + stats.benignFlows + stats.uncertainFlows;
    final threatRate = total > 0
        ? (stats.totalThreats / total * 100).toStringAsFixed(1)
        : '0.0';

    // Pre-fetch SHAP explanations for all non-UNKNOWN threat flows (up to the 100-row table limit).
    // UNKNOWN flows are OSR-rejected — SHAP on a rejected flow is not meaningful, so they are skipped.
    // Runs concurrently. Any flow no longer in the detection buffer returns null → static fallback.
    final shapCache = <String, List<String>>{}; // flowId → top 3 feature labels
    final shapCandidates = log
        .take(100)
        .where((e) => e.flowId != null && !e.isNovel && e.type != 'UNKNOWN')
        .toList();
    if (shapCandidates.isNotEmpty) {
      final results = await Future.wait(
        shapCandidates.map((e) => provider.fetchExplanation(e.flowId!)),
      );
      for (var i = 0; i < shapCandidates.length; i++) {
        final data = results[i];
        if (data == null) continue;
        final shapValues = data['shap_values'] as Map<String, dynamic>?;
        final predictedClass = data['predicted_class'] as String?;
        if (shapValues == null || predictedClass == null) continue;
        final classEntries = shapValues[predictedClass] as List<dynamic>?;
        if (classEntries == null || classEntries.isEmpty) continue;
        final labels = classEntries.take(3).map((e) {
          final raw = e['feature'] as String;
          final dir = (e['shap'] as num).toDouble() >= 0 ? 'high' : 'low';
          return '${_shapFeatureLabel(raw)} ($dir)';
        }).toList();
        shapCache[shapCandidates[i].flowId!] = labels;
      }
    }

    // Color palette
    const headerBg    = PdfColor.fromInt(0xFF1A3C2E);
    const accentGreen = PdfColor.fromInt(0xFF2E7D52);
    const criticalRed = PdfColor.fromInt(0xFFB71C1C);
    const highOrange  = PdfColor.fromInt(0xFFE65100);
    const mediumYellow= PdfColor.fromInt(0xFFF57F17);
    const lowGreen    = PdfColor.fromInt(0xFF1B5E20);
    const infoBlue    = PdfColor.fromInt(0xFF1565C0);
    const rowAlt      = PdfColor.fromInt(0xFFF4F7F5);
    const borderGrey  = PdfColor.fromInt(0xFFDDE3DF);
    const textDark    = PdfColor.fromInt(0xFF1A1A1A);
    const textMid     = PdfColor.fromInt(0xFF4A5568);
    const textMuted   = PdfColor.fromInt(0xFF718096);
    const white       = PdfColors.white;

    // ── Shared builder helpers ─────────────────────────────────────────────

    pw.TextStyle ts(
      double size, {
      PdfColor color = textDark,
      bool bold = false,
      bool italic = false,
      bool mono = false,
      double? letterSpacing,
      double? lineSpacing,
    }) {
      pw.Font base;
      if (mono) {
        base = bold ? fontMonoBold : fontMono;
      } else if (bold) {
        base = fontBold;
      } else if (italic) {
        base = fontItalic;
      } else {
        base = fontRegular;
      }
      return pw.TextStyle(
        font: base,
        fontSize: size,
        color: color,
        letterSpacing: letterSpacing,
        lineSpacing: lineSpacing,
      );
    }

    pw.Widget sectionHeader(String number, String title) => pw.Container(
          margin: const pw.EdgeInsets.only(top: 18, bottom: 8),
          child: pw.Row(children: [
            pw.Container(
              width: 22,
              height: 22,
              decoration: const pw.BoxDecoration(color: accentGreen),
              child: pw.Center(
                  child: pw.Text(number,
                      style: ts(10, color: white, bold: true))),
            ),
            pw.SizedBox(width: 8),
            pw.Text(title, style: ts(13, bold: true)),
            pw.SizedBox(width: 10),
            pw.Expanded(child: pw.Divider(color: borderGrey, thickness: 1)),
          ]),
        );

    pw.Widget pill(String label, PdfColor color) => pw.Container(
          padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 2),
          decoration: pw.BoxDecoration(
            color: _lightBg(color, 0.15),
            border: pw.Border.all(
                color: _lightBorder(color, 0.45), width: 0.5),
            borderRadius: const pw.BorderRadius.all(pw.Radius.circular(3)),
          ),
          child: pw.Text(label, style: ts(7, color: color, bold: true)),
        );

    pw.Widget kpiBox(String label, String value, PdfColor color) =>
        pw.Expanded(
            child: pw.Container(
          padding: const pw.EdgeInsets.all(10),
          margin: const pw.EdgeInsets.only(right: 8),
          decoration: pw.BoxDecoration(
            color: _lightBg(color, 0.10),           // pale tint, fully opaque
            border: pw.Border.all(
                color: _lightBorder(color, 0.35), width: 0.5),
            borderRadius: const pw.BorderRadius.all(pw.Radius.circular(4)),
          ),
          child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                pw.Text(value,
                    style: ts(18, color: color, bold: true, mono: true)),
                pw.SizedBox(height: 2),
                pw.Text(label, style: ts(8, color: textMuted)),
              ]),
        ));

    pw.Widget thCell(String label, {int flex = 1}) => pw.Expanded(
        flex: flex,
        child: pw.Text(label, style: ts(8, color: white, bold: true)));

    pw.Widget tdCell(String label,
            {int flex = 1,
            PdfColor color = textDark,
            bool mono = false}) =>
        pw.Expanded(
            flex: flex,
            child: pw.Text(label,
                style: mono
                    ? ts(7.5, color: color, mono: true)
                    : ts(7.5, color: color),
                overflow: pw.TextOverflow.clip));

    // ── Page 1 ─────────────────────────────────────────────────────────────
    final doc = pw.Document(
      title: 'Threat Analysis Report',
      author: 'ThreatMatrix: An Adaptive Threat Behavioural Analysis Framework',
    );

    doc.addPage(pw.MultiPage(
      pageFormat: PdfPageFormat.a4,
      margin: const pw.EdgeInsets.all(0),
      header: (ctx) {
        // Page 1 has the full-bleed cover bar built inside the body — no running header.
        if (ctx.pageNumber == 1) return pw.SizedBox();
        return pw.Container(
          padding: const pw.EdgeInsets.fromLTRB(32, 24, 32, 8),
          decoration: const pw.BoxDecoration(
              border: pw.Border(
                  bottom: pw.BorderSide(color: borderGrey, width: 0.5))),
          child: pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text('ThreatMatrix - An Adaptive Threat Behavioural Analysis Framework',
                    style: ts(8, color: textMuted)),
                pw.Text('All Available Data  -  ${_formatDate(now)}',
                    style: ts(8, color: textMuted)),
              ]),
        );
      },
      footer: (ctx) => pw.Container(
        padding: const pw.EdgeInsets.fromLTRB(32, 6, 32, 24),
        decoration: const pw.BoxDecoration(
            border: pw.Border(
                top: pw.BorderSide(color: borderGrey, width: 0.5))),
        child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Text('CONFIDENTIAL - TLP:RED',
                  style: ts(7, color: criticalRed, bold: true)),
              pw.Text('Page ${ctx.pageNumber} of ${ctx.pagesCount}',
                  style: ts(7, color: textMuted)),
            ]),
      ),
      build: (ctx) => [
        // Top header bar
        pw.Container(
          color: headerBg,
          padding: const pw.EdgeInsets.symmetric(horizontal: 32, vertical: 20),
          child: pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Row(children: [
                        pw.Container(
                          width: 10, height: 10,
                          margin: const pw.EdgeInsets.only(right: 8, top: 2),
                          decoration: const pw.BoxDecoration(
                              color: accentGreen,
                              shape: pw.BoxShape.circle),
                        ),
                        pw.Text('THREATMATRIX',
                            style: ts(20, color: white, bold: true,
                                letterSpacing: 2)),
                      ]),
                      pw.SizedBox(height: 4),
                      pw.Text('Network Threat Behavioural Analysis Report',
                          style: ts(10,
                              color: const PdfColor(1, 1, 1, 0.75))),
                    ]),
                pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.end,
                    children: [
                      pw.Text('Generated: ${_formatDate(now)}',
                          style: ts(8,
                              color: const PdfColor(1, 1, 1, 0.85))),
                      pw.SizedBox(height: 3),
                      pw.Text('Period: All Available Data',
                          style: ts(8,
                              color: const PdfColor(1, 1, 1, 0.85))),
                      pw.SizedBox(height: 3),
                      pw.Container(
                        padding: const pw.EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: const pw.BoxDecoration(
                            color: criticalRed,
                            borderRadius: pw.BorderRadius.all(
                                pw.Radius.circular(3))),
                        // FIX-C: no special characters in label
                        child: pw.Text('TLP:RED  CONFIDENTIAL',
                            style: ts(8, color: white, bold: true)),
                      ),
                    ]),
              ]),
        ),

        // Findings summary strip
        // FIX-1: horizontal padding reduced from 32 → 20 to align with NIST phase bar below
        pw.Container(
          color: const PdfColor.fromInt(0xFF0F2D20),
          padding:
              const pw.EdgeInsets.symmetric(horizontal: 20, vertical: 10),
          child: pw.Row(children: [
            pw.Text('FINDINGS SUMMARY',
                style: ts(8,
                    color: const PdfColor(1, 1, 1, 0.65),
                    bold: true,
                    letterSpacing: 1)),
            pw.SizedBox(width: 16),
            pill('CRITICAL  ${stats.exploitCount}',
                criticalRed),
            pw.SizedBox(width: 6),
            pill('HIGH  ${stats.credAbuseCount}', highOrange),
            pw.SizedBox(width: 6),
            pill('MEDIUM  ${stats.uncertainFlows}', mediumYellow),
            pw.SizedBox(width: 6),
            pill('LOW  ${stats.benignFlows}', lowGreen),
            pw.Spacer(),
            // FIX-C: hyphen instead of middle-dot
            pw.Text(
                'Total Flows: $total  -  Threat Rate: $threatRate%',
                style: ts(8,
                    color: stats.totalThreats > 0
                        ? criticalRed
                        : const PdfColor(1, 1, 1, 0.75),
                    bold: true)),
          ]),
        ),

        // NIST SP 800-61 Rev.2 Incident Response Phase indicator
        pw.Container(
          color: const PdfColor.fromInt(0xFF0D2A1A),
          padding: const pw.EdgeInsets.symmetric(horizontal: 20, vertical: 7),
          child: pw.Row(children: [
            pw.Text('NIST SP 800-61r2 IR PHASE:',
                style: ts(6.5, color: const PdfColor(1, 1, 1, 0.55), bold: true, letterSpacing: 0.6)),
            pw.SizedBox(width: 8),
            for (final ph in <(String, bool)>[
              ('1 Preparation', true),
              ('2 Detection & Analysis', true),
              ('3 Containment', stats.totalThreats > 0),
              ('4 Eradication', false),
              ('5 Recovery', false),
              ('6 Post-Incident', false),
            ]) pw.Container(
              margin: const pw.EdgeInsets.only(right: 4),
              padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: pw.BoxDecoration(
                color: ph.$2
                    ? _lightBg(stats.totalThreats > 0 && ph.$1.contains('3')
                        ? criticalRed : accentGreen, 0.18)
                    : const PdfColor(0.15, 0.15, 0.15),
                borderRadius: const pw.BorderRadius.all(pw.Radius.circular(3)),
                border: pw.Border.all(
                    color: ph.$2 ? accentGreen : const PdfColor(0.35, 0.35, 0.35),
                    width: 0.5),
              ),
              child: pw.Text(ph.$1,
                  style: ts(6.5,
                      color: ph.$2
                          ? (stats.totalThreats > 0 && ph.$1.contains('3')
                              ? criticalRed : accentGreen)
                          : const PdfColor(0.55, 0.55, 0.55),
                      bold: ph.$2)),
            ),
          ]),
        ),

        // Section 1 — Training Features
        pw.Padding(
          padding: const pw.EdgeInsets.fromLTRB(32, 16, 32, 0),
          child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [

            // 1. Training Features — Behavioural Signal Reference
            sectionHeader('1', 'Training Features — Behavioural Signal Reference'),
            pw.SizedBox(height: 6),
            pw.Text(
              'ThreatMatrix does not inspect packet contents. It classifies threats from '
              '16 flow-level statistics that describe how traffic behaves between two endpoints, '
              'making the model protocol-agnostic and resilient to tool variation.',
              style: ts(8, color: textMid, lineSpacing: 2.5)),
            pw.SizedBox(height: 6),
            pw.Container(
              color: accentGreen,
              padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 4),
              child: pw.Row(children: [
                pw.Expanded(flex: 5, child: pw.Text('Feature', style: ts(7.5, color: white, bold: true))),
                pw.Expanded(flex: 2, child: pw.Text('Group', style: ts(7.5, color: white, bold: true))),
                pw.Expanded(flex: 7, child: pw.Text('Behavioural Significance', style: ts(7.5, color: white, bold: true))),
              ]),
            ),
            ..._buildFeatureRows(accentGreen, textDark, textMid, ts),
            pw.SizedBox(height: 4),
            pw.Container(
              width: double.infinity,
              padding: const pw.EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: pw.BoxDecoration(
                color: _lightBg(accentGreen, 0.10),
                borderRadius: const pw.BorderRadius.all(pw.Radius.circular(3))),
              child: pw.Text(
                '* fwd_header_size_tot and bwd_header_size_tot are used in Phase 1 (binary Benign vs. Attack classification) only. '
                'TLS overhead inflates these values in a way that reflects protocol choice rather than attack behaviour, '
                'so they are excluded from Phase 2 (multiclass severity routing) and Phase 3 (fine-grained classification with open-set novel attack detection).',
                style: ts(7, color: textMid, lineSpacing: 2)),
            ),
            pw.SizedBox(height: 12),
          ]),
        ),

        // Section 2 — Executive Summary
        pw.Padding(
          padding: const pw.EdgeInsets.fromLTRB(32, 0, 32, 0),
          child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [

            // 2. Executive Summary
            sectionHeader('2', 'Executive Summary'),
            pw.Row(children: [
              kpiBox('Threats', stats.totalThreats.toString(),
                  stats.totalThreats > 0 ? criticalRed : accentGreen),
              kpiBox('Benign', stats.benignFlows.toString(), accentGreen),
              kpiBox('Uncertain', stats.uncertainFlows.toString(),
                  mediumYellow),
              kpiBox('Risk Score',
                  '${provider.riskScore.toStringAsFixed(0)}/100',
                  provider.riskScore >= 50 ? criticalRed : accentGreen),
              // FIX-A: Confidence box — same opaque approach
              pw.Expanded(
                  child: pw.Container(
                padding: const pw.EdgeInsets.all(10),
                margin: const pw.EdgeInsets.only(right: 0),
                decoration: pw.BoxDecoration(
                  color: _lightBg(accentGreen, 0.10),
                  border: pw.Border.all(
                      color: _lightBorder(accentGreen, 0.35),
                      width: 0.5),
                  borderRadius:
                      const pw.BorderRadius.all(pw.Radius.circular(4)),
                ),
                child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(
                          stats.modelAccuracy > 0
                              ? '${stats.modelAccuracy.toStringAsFixed(1)}%'
                              : '--',
                          style: ts(18, color: accentGreen, bold: true,
                              mono: true)),
                      pw.SizedBox(height: 2),
                      pw.Text('Confidence',
                          style: ts(8, color: textMuted)),
                    ]),
              )),
            ]),
            pw.SizedBox(height: 10),
            pw.Container(
              padding: const pw.EdgeInsets.all(12),
              decoration: pw.BoxDecoration(
                color: rowAlt,
                border: pw.Border.all(color: borderGrey, width: 0.5),
                borderRadius:
                    const pw.BorderRadius.all(pw.Radius.circular(4)),
              ),
              child: pw.Text(
                stats.totalThreats == 0
                    ? 'No confirmed threat events were detected during the selected monitoring period. '
                    : 'A total of ${stats.totalThreats} confirmed threat events were detected, representing a threat rate of $threatRate% among all observed network flows. The risk score for this period is ${provider.riskScore.toStringAsFixed(0)}/100.',
                style: ts(9, color: textMid, lineSpacing: 3),
              ),
            ),
          ]),
        ),

        // Section 3 — MITRE ATT&CK
        pw.Padding(
          padding: const pw.EdgeInsets.fromLTRB(32, 0, 32, 0),
          child: pw.Column(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [

            // 3. MITRE ATT&CK
            sectionHeader('3', 'MITRE ATT&CK Technique Coverage'),
            if (stats.totalThreats == 0)
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(
                    color: rowAlt,
                    border: pw.Border.all(color: borderGrey, width: 0.5),
                    borderRadius:
                        const pw.BorderRadius.all(pw.Radius.circular(4))),
                child: pw.Text('No MITRE techniques triggered in this period.',
                    style: ts(9, color: textMuted)),
              )
            else ...[
              pw.Container(
                color: headerBg,
                padding: const pw.EdgeInsets.symmetric(
                    horizontal: 10, vertical: 7),
                child: pw.Row(children: [
                  thCell('Technique ID', flex: 2),
                  thCell('Technique Name', flex: 4),
                  thCell('Tactic', flex: 2),
                  thCell('Count', flex: 1),
                  thCell('Severity', flex: 2),
                ]),
              ),
              if (stats.reconCount > 0)
                _mitrePdfRow(true, 'T1595.001',
                    'Active Scanning: Scanning IP Blocks', 'TA0043 Reconnaissance',
                    stats.reconCount, 'Critical', criticalRed,
                    rowAlt, textDark, infoBlue, pill, ts),
              if (stats.credAbuseCount > 0)
                _mitrePdfRow(stats.reconCount % 2 == 0, 'T1110',
                    'Brute Force: Password Guessing', 'TA0006 Cred. Access',
                    stats.credAbuseCount, 'High', highOrange,
                    rowAlt, textDark, infoBlue, pill, ts),
              if (stats.exploitCount > 0)
                _mitrePdfRow(
                    (stats.reconCount + stats.credAbuseCount) % 2 == 0,
                    'T1190',
                    'Exploit Public-Facing Application',
                    'TA0001 Initial Access',
                    stats.exploitCount,
                    'Critical',
                    criticalRed,
                    rowAlt,
                    textDark,
                    infoBlue,
                    pill,
                    ts),
              if (stats.novelCount > 0)
                _mitrePdfRow(
                    (stats.reconCount + stats.credAbuseCount + stats.exploitCount) % 2 == 0,
                    'T0000',
                    'Unknown / Novel — Unseen During Training',
                    'Phase 3 OSR',
                    stats.novelCount,
                    'Critical',
                    const PdfColor.fromInt(0xFF6A1B9A),
                    rowAlt,
                    textDark,
                    const PdfColor.fromInt(0xFF6A1B9A),
                    pill,
                    ts),
            ],
          ]),
        ),

        // 4. Correlated Incidents — wrapped in same horizontal:32 padding as sections 2 & 3
        pw.Padding(
          padding: const pw.EdgeInsets.symmetric(horizontal: 32),
          child: pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.SizedBox(height: 4),
              sectionHeader('4', 'Correlated Incidents'),
              pw.SizedBox(height: 8),
              if (provider.incidents.isEmpty)
                pw.Container(
                  margin: const pw.EdgeInsets.only(bottom: 6),
                  padding: const pw.EdgeInsets.all(10),
                  decoration: pw.BoxDecoration(
                      color: rowAlt,
                      border: pw.Border.all(color: borderGrey, width: 0.5),
                      borderRadius:
                          const pw.BorderRadius.all(pw.Radius.circular(4))),
                  child: pw.Text('No correlated incidents in this period.',
                      style: ts(9, color: textMuted)),
                )
              else
                ...provider.incidents.take(10).toList().map((inc) {
                  final c = inc.severity == 'Critical'
                      ? criticalRed
                      : inc.severity == 'High'
                          ? highOrange
                          : mediumYellow;
                  return pw.Container(
                    margin: const pw.EdgeInsets.only(bottom: 6),
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: borderGrey, width: 0.5),
                      borderRadius:
                          const pw.BorderRadius.all(pw.Radius.circular(4)),
                    ),
                    child: pw.Row(children: [
                      pw.Container(
                          width: 4, height: 40,
                          decoration: pw.BoxDecoration(
                              color: c,
                              borderRadius: const pw.BorderRadius.horizontal(
                                  left: pw.Radius.circular(4)))),
                      pw.SizedBox(width: 10),
                      pw.Expanded(
                          child: pw.Column(
                              crossAxisAlignment: pw.CrossAxisAlignment.start,
                              children: [
                            pw.Row(children: [
                              pw.Text(inc.incidentId, style: ts(9, bold: true)),
                              pw.SizedBox(width: 6),
                              pill(inc.severity, c),
                            ]),
                            pw.SizedBox(height: 2),
                            pw.Text(inc.description, style: ts(8, color: textMid)),
                          ])),
                      pw.Padding(
                        padding: const pw.EdgeInsets.only(right: 12),
                        child: pw.Text(
                            '${inc.count} event${inc.count > 1 ? "s" : ""}',
                            style: ts(9, color: c, bold: true)),
                      ),
                    ]),
                  );
                }),
            ],
          ),
        ),
      ],
    ));

    // ── Page 2 — Detailed Threat Findings ────
    doc.addPage(pw.MultiPage(
      pageFormat: PdfPageFormat.a4.landscape,
      margin: const pw.EdgeInsets.fromLTRB(32, 24, 32, 24),
      header: (ctx) => pw.Container(
        padding: const pw.EdgeInsets.only(bottom: 8),
        decoration: const pw.BoxDecoration(
            border: pw.Border(
                bottom: pw.BorderSide(color: borderGrey, width: 0.5))),
        child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Text('ThreatMatrix - An Adaptive Threat Behavioural Analysis Framework',
                  style: ts(8, color: textMuted)),
              pw.Text('All Available Data  -  ${_formatDate(now)}',
                  style: ts(8, color: textMuted)),
            ]),
      ),
      footer: (ctx) => pw.Container(
        padding: const pw.EdgeInsets.only(top: 6),
        decoration: const pw.BoxDecoration(
            border: pw.Border(
                top: pw.BorderSide(color: borderGrey, width: 0.5))),
        child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Text('CONFIDENTIAL - TLP:RED',
                  style: ts(7, color: criticalRed, bold: true)),
              pw.Text('Page ${ctx.pageNumber} of ${ctx.pagesCount}',
                  style: ts(7, color: textMuted)),
            ]),
      ),
      build: (ctx) => [
        pw.SizedBox(height: 16),
        pw.Row(children: [
          pw.Container(
            width: 22, height: 22,
            decoration: const pw.BoxDecoration(color: accentGreen),
            child: pw.Center(
                child: pw.Text('5',
                    style: ts(10, color: white, bold: true))),
          ),
          pw.SizedBox(width: 8),
          pw.Text('Detailed Threat Findings',
              style: ts(13, bold: true)),
          pw.SizedBox(width: 10),
          pw.Expanded(child: pw.Divider(color: borderGrey, thickness: 1)),
        ]),
        pw.SizedBox(height: 8),

        if (log.isEmpty)
          pw.Container(
            padding: const pw.EdgeInsets.all(10),
            decoration: pw.BoxDecoration(
                color: rowAlt,
                border: pw.Border.all(color: borderGrey, width: 0.5),
                borderRadius:
                    const pw.BorderRadius.all(pw.Radius.circular(4))),
            child: pw.Text(
                'No threat findings recorded in this period.',
                style: ts(9, color: textMuted)),
          )
        else ...[
          pw.Container(
            color: headerBg,
            padding:
                const pw.EdgeInsets.symmetric(horizontal: 8, vertical: 6),
            child: pw.Row(children: [
              thCell('ID', flex: 2),
              thCell('Timestamp', flex: 3),
              thCell('Origin IP', flex: 3),
              thCell('Destination IP', flex: 3),
              thCell('MITRE', flex: 2),
              thCell('Severity', flex: 2),
              thCell('Confidence', flex: 2),
              thCell('Kill Chain', flex: 3),
              thCell('Key Signals', flex: 4),
            ]),
          ),
          ...log.take(100).toList().asMap().entries.map((e) {
            final entry = e.value;
            final isEven = e.key % 2 == 0;
            final sevColor = entry.severity == 'Critical'
                ? criticalRed
                : entry.severity == 'High'
                    ? highOrange
                    : entry.severity == 'Medium'
                        ? mediumYellow
                        : lowGreen;
            final conf = entry.modelConfidence != null
                ? '${(entry.modelConfidence! * 100).toStringAsFixed(1)}%'
                : entry.attackProbability != null
                    ? '${(entry.attackProbability! * 100).toStringAsFixed(1)}%'
                    : '--';
            // Key Signals: UNKNOWN flows have no SHAP (OSR-rejected — not meaningful).
            // All other flows: live SHAP top 3 if in buffer, otherwise static type-based fallback.
            final String signals;
            if (entry.isNovel || entry.type == 'UNKNOWN') {
              signals = 'Novel / out-of-distribution pattern';
            } else if (entry.flowId != null && shapCache.containsKey(entry.flowId)) {
              signals = shapCache[entry.flowId]!.join('  ·  ');
            } else {
              // Static fallback when buffer has evicted the flow
              final t = entry.type.toLowerCase();
              if (t.contains('scan') || t.contains('recon')) {
                signals = 'Packet rate (high)  ·  Payload (low)  ·  SYN flags (high)';
              } else if (t.contains('brute') || t.contains('cred')) {
                signals = 'Flow duration (short)  ·  DL/UL ratio (low)  ·  FIN flags (high)';
              } else if (t.contains('sql') || t.contains('exploit')) {
                signals = 'Fwd data pkts (high)  ·  Payload (high)  ·  Bwd pkts (low)';
              } else {
                signals = 'Anomalous flow profile';
              }
            }
            return pw.Container(
              color: isEven ? PdfColors.white : rowAlt,
              padding: const pw.EdgeInsets.symmetric(
                  horizontal: 8, vertical: 5),
              child: pw.Row(children: [
                tdCell(entry.id, flex: 2, color: accentGreen, mono: true),
                tdCell(entry.formattedTimestamp, flex: 3, color: textMid),
                tdCell(entry.originIp ?? '--', flex: 3),
                tdCell(entry.destinationIp ?? '--', flex: 3),
                tdCell(entry.mitreInfo?.techniqueId ?? '--',
                    flex: 2, color: infoBlue, mono: true),
                pw.Expanded(flex: 2, child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [pill(entry.severity, sevColor)])),
                tdCell(conf, flex: 2, color: textMid, mono: true),
                tdCell(entry.killChainPhase ?? '--', flex: 3, color: textMid),
                tdCell(signals, flex: 4, color: textMid),
              ]),
            );
          }),
          if (log.length > 100)
            pw.Padding(
              padding: const pw.EdgeInsets.only(top: 4),
              child: pw.Text(
                  '${log.length - 100} additional entries omitted. Full dataset available in CSV/JSON export.',
                  style: ts(8, color: textMuted, italic: true)),
            ),
          pw.SizedBox(height: 6),
          pw.Text(
            'Key signals show the top 3 behavioural features that most influenced the model\'s decision for each flow. '
            'Full per-flow explanation is available in the Threat Log at the main dashboard.',
            style: ts(7, color: textMuted, italic: true)),
        ],

        // Page 3 — Recommendations (portrait)
      ],
    ));

    // ── Page 3 — Recommendations + Dataset Context (Portrait) ──────────────
    doc.addPage(pw.MultiPage(
      pageFormat: PdfPageFormat.a4,
      margin: const pw.EdgeInsets.fromLTRB(32, 24, 32, 24),
      header: (ctx) => pw.Container(
        padding: const pw.EdgeInsets.only(bottom: 8),
        decoration: const pw.BoxDecoration(
            border: pw.Border(
                bottom: pw.BorderSide(color: borderGrey, width: 0.5))),
        child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Text('ThreatMatrix - An Adaptive Threat Behavioural Analysis Framework',
                  style: ts(8, color: textMuted)),
              pw.Text('All Available Data  -  ${_formatDate(now)}',
                  style: ts(8, color: textMuted)),
            ]),
      ),
      footer: (ctx) => pw.Container(
        padding: const pw.EdgeInsets.only(top: 6),
        decoration: const pw.BoxDecoration(
            border: pw.Border(
                top: pw.BorderSide(color: borderGrey, width: 0.5))),
        child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Text('CONFIDENTIAL - TLP:RED',
                  style: ts(7, color: criticalRed, bold: true)),
              pw.Text('Page ${ctx.pageNumber} of ${ctx.pagesCount}',
                  style: ts(7, color: textMuted)),
            ]),
      ),
      build: (ctx) => [
        // 6. Recommendations
        pw.SizedBox(height: 16),
        pw.Row(children: [
          pw.Container(
            width: 22, height: 22,
            decoration: const pw.BoxDecoration(color: accentGreen),
            child: pw.Center(
                child: pw.Text('6',
                    style: ts(10, color: white, bold: true))),
          ),
          pw.SizedBox(width: 8),
          pw.Text('Recommendations',
              style: ts(13, bold: true)),
          pw.SizedBox(width: 10),
          pw.Expanded(child: pw.Divider(color: borderGrey, thickness: 1)),
        ]),
        pw.SizedBox(height: 8),

        ..._buildPdfRecommendations(
            stats, provider, pill, ts,
            criticalRed, highOrange, mediumYellow, accentGreen,
            textDark, textMid, textMuted, white, borderGrey),

      ],
    ));

    // Strip the .pdf extension from the name — the Printing package (and the
    // system print/save dialog on Windows, macOS and Chrome) appends ".pdf"
    // automatically.  Passing the extension here produces "…_ts.pdf.pdf".
    final pdfName = filename.endsWith('.pdf')
        ? filename.substring(0, filename.length - 4)
        : filename;
    await Printing.layoutPdf(
      name: pdfName,
      onLayout: (_) async => doc.save(),
    );
  }

  pw.Widget _mitrePdfRow(
    bool isAlt,
    String id,
    String name,
    String tactic,
    int count,
    String severity,
    PdfColor sevColor,
    PdfColor rowAlt,
    PdfColor textDark,
    PdfColor infoBlue,
    pw.Widget Function(String, PdfColor) pill,
    pw.TextStyle Function(double, {PdfColor color, bool bold, bool italic, bool mono, double? letterSpacing, double? lineSpacing}) ts,
  ) {
    return pw.Container(
      color: isAlt ? rowAlt : PdfColors.white,
      padding: const pw.EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      child: pw.Row(children: [
        pw.Expanded(
            flex: 2,
            child: pw.Text(id,
                style: ts(8, color: infoBlue, bold: true, mono: true))),
        pw.Expanded(
            flex: 4,
            child: pw.Text(name, style: ts(8, color: textDark))),
        pw.Expanded(
            flex: 2,
            child: pw.Text(tactic, style: ts(8, color: textDark))),
        pw.Expanded(
            flex: 1,
            child: pw.Text(count.toString(),
                style: ts(8, color: sevColor, bold: true))),
        pw.Expanded(flex: 2, child: pill(severity, sevColor)),
      ]),
    );
  }

  // Readable display label for a raw SHAP feature column name (PDF + dashboard shared)
  static String _shapFeatureLabel(String raw) {
    const map = {
      'flow_duration':            'Flow duration',
      'fwd_pkts_tot':             'Fwd packets',
      'bwd_pkts_tot':             'Bwd packets',
      'fwd_data_pkts_tot':        'Fwd data pkts',
      'bwd_data_pkts_tot':        'Bwd data pkts',
      'flow_pkts_per_sec':        'Packet rate',
      'fwd_pkts_per_sec':         'Fwd pkt rate',
      'bwd_pkts_per_sec':         'Bwd pkt rate',
      'payload_bytes_per_second': 'Payload throughput',
      'down_up_ratio':            'DL/UL ratio',
      'fwd_header_size_tot':      'Fwd header size',
      'bwd_header_size_tot':      'Bwd header size',
      'flow_FIN_flag_count':      'FIN flags',
      'flow_SYN_flag_count':      'SYN flags',
      'flow_RST_flag_count':      'RST flags',
      'flow_ACK_flag_count':      'ACK flags',
    };
    return map[raw] ?? raw;
  }

  List<pw.Widget> _buildFeatureRows(
    PdfColor accentGreen,
    PdfColor textDark,
    PdfColor textMid,
    pw.TextStyle Function(double,
            {PdfColor color,
            bool bold,
            bool italic,
            bool mono,
            double? letterSpacing,
            double? lineSpacing})
        ts,
  ) {
    // Each entry: [feature_name, group, behavioural_significance]
    // Features sourced directly from UNIVERSAL_FEATURES in all 3 training scripts.
    // Phase 1 (binary): 16 features (includes header size totals).
    // Phases 2 and 3: 14 features (header size totals dropped due to TLS fingerprint risk).
    final features = <List<String>>[
      // ── Flow Volume ───────────────────────────────────────────────────────
      ['flow_duration',            'Flow Volume', 'Scan flows are extremely brief. Brute-force attempts tend to repeat over a longer window.'],
      ['fwd_pkts_tot',             'Flow Volume', 'Attackers typically send a high volume of small packets when probing a target.'],
      ['bwd_pkts_tot',             'Flow Volume', 'A closed port produces no response. Low backward count is a strong indicator of scanning activity.'],
      ['fwd_data_pkts_tot',        'Flow Volume', 'Injection attacks embed payload in request bodies, pushing this count higher than normal.'],
      ['bwd_data_pkts_tot',        'Flow Volume', 'When the server rejects a probe, it returns no data and this count drops to near zero.'],
      // ── Rate ─────────────────────────────────────────────────────────────
      ['flow_pkts_per_sec',        'Rate',        'Automated tools generate packets at a rate no human user would produce naturally.'],
      ['fwd_pkts_per_sec',         'Rate',        'Brute-force tools send requests at a mechanically consistent rate from the client side.'],
      ['bwd_pkts_per_sec',         'Rate',        'A target with no open service produces no replies, pulling this rate toward zero.'],
      ['payload_bytes_per_second', 'Rate',        'Injection attacks carry dense request payloads. Reconnaissance activity carries almost none.'],
      // ── Direction Asymmetry ───────────────────────────────────────────────
      ['down_up_ratio',            'Asymmetry',   'Legitimate sessions are roughly balanced. Attack traffic is heavily skewed toward the client, keeping this ratio low.'],
      // ── Header Overhead (Phase 1 only) ────────────────────────────────────
      ['fwd_header_size_tot *',    'Header (P1)', 'Helps separate benign from attack traffic at the binary stage. Excluded later as TLS inflates this value regardless of intent.'],
      ['bwd_header_size_tot *',    'Header (P1)', 'Captures server-side header overhead. Helps separate benign from attack traffic at the binary stage. Excluded later as TLS inflates this value regardless of intent.'],
      // ── TCP Flags ─────────────────────────────────────────────────────────
      ['flow_FIN_flag_count',      'TCP Flags',   'Legitimate sessions close gracefully with FIN. Scanners simply abandon or reset the connection.'],
      ['flow_SYN_flag_count',      'TCP Flags',   'A flood of SYN packets with no subsequent ACK is the textbook signature of a port scan.'],
      ['flow_RST_flag_count',      'TCP Flags',   'High RST counts reflect probes being rejected by closed or filtered ports.'],
      ['flow_ACK_flag_count',      'TCP Flags',   'No ACK means the three-way handshake was never completed, which is characteristic of scan traffic.'],
    ];

    final rowAlt = _lightBg(accentGreen, 0.04);
    return features.asMap().entries.map((entry) {
      final isAlt = entry.key.isOdd;
      final f = entry.value;
      return pw.Container(
        color: isAlt ? rowAlt : PdfColors.white,
        padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 4),
        child: pw.Row(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.Expanded(
                  flex: 5,
                  child: pw.Text(f[0],
                      style: ts(7, color: textDark, mono: true))),
              pw.Expanded(
                  flex: 2,
                  child: pw.Text(f[1],
                      style: ts(7, color: accentGreen))),
              pw.Expanded(
                  flex: 7,
                  child: pw.Text(f[2],
                      style: ts(7, color: textMid, lineSpacing: 1.8))),
            ]),
      );
    }).toList();
  }

  List<pw.Widget> _buildPdfRecommendations(
    DashboardStats stats,
    ThreatMatrixProvider provider,
    pw.Widget Function(String, PdfColor) pill,
    pw.TextStyle Function(double, {PdfColor color, bool bold, bool italic, bool mono, double? letterSpacing, double? lineSpacing}) ts,
    PdfColor criticalRed,
    PdfColor highOrange,
    PdfColor mediumYellow,
    PdfColor accentGreen,
    PdfColor textDark,
    PdfColor textMid,
    PdfColor textMuted,
    PdfColor white,
    PdfColor borderGrey,
  ) {
    final recs = <({
      String priority,
      PdfColor color,
      String title,
      String detail,
      String steps
    })>[];

    if (stats.reconCount > 0) {
      recs.add((
        priority: 'CRITICAL',
        color: criticalRed,
        title: 'Investigate Reconnaissance Activity',
        detail:
            'T1046/T1595.001 - Network scanning detected. Monitor for follow-on activity.',
        steps:
            '1. Log and monitor source IPs\n2. Update IDS/IPS signatures for scanning patterns\n3. Review exposed services and close unnecessary ports\n4. Correlate with subsequent attack activity\n5. Document source IPs for incident correlation'
      ));
    }
    if (stats.exploitCount > 0) {
      recs.add((
        priority: 'CRITICAL',
        color: criticalRed,
        title: 'Remediate Active Exploitation Attempt',
        detail:
            'T1190 - SQL injection via HTTP/HTTPS detected. Potential data breach risk.',
        steps:
            '1. Block the source IP at the network boundary and review web application firewall rules if available\n2. Audit application logs for successful exploitation indicators\n3. Engage the development team for an emergency patch\n4. Isolate the affected host until remediation is confirmed'
      ));
    }
    if (stats.credAbuseCount > 0) {
      recs.add((
        priority: 'HIGH',
        color: highOrange,
        title: 'Harden Authentication Controls',
        detail: 'T1110 - Credential abuse attacks detected (HTTP/HTTPS brute force).',
        steps:
            '1. Enforce account lockout after repeated failed attempts\n2. Enable MFA on all administrative and privileged accounts\n3. Audit authentication logs for successful follow-on access\n4. Configure login rate limiting on authentication services\n5. Rotate credentials for targeted accounts'
      ));
    }
    if (stats.uncertainFlows > 0) {
      recs.add((
        priority: 'MEDIUM',
        color: mediumYellow,
        title: 'Investigate Anomalous Flows',
        detail:
            '${stats.uncertainFlows} UNCERTAIN flows flagged for Phase 3 open-set classifier review.',
        steps:
            '1. Capture full packet data (PCAP) from the flagged source IP for further inspection\n2. Review the Phase 1 detection sensitivity in ThreatMatrix settings if false positives are suspected\n3. Seek expert review if Phase 3 classifies the flow as UNKNOWN\n4. Document findings for future model evaluation'
      ));
    }
    if (recs.isEmpty) {
      recs.add((
        priority: 'INFO',
        color: accentGreen,
        title: 'Maintain Monitoring Posture',
        detail: 'No active threats detected. System operating normally.',
        steps:
            '1. Continue live flow monitoring\n2. Review ThreatMatrix detection logs periodically to confirm normal baseline\n3. Review detection thresholds quarterly\n4. Schedule next threat assessment in 30 days'
      ));
    }

    return recs
        .map((rec) => pw.Container(
              margin: const pw.EdgeInsets.only(bottom: 10),
              decoration: pw.BoxDecoration(
                border: pw.Border.all(
                    color: _lightBorder(rec.color, 0.45), width: 0.5),
                borderRadius:
                    const pw.BorderRadius.all(pw.Radius.circular(4)),
              ),
              child: pw.Column(children: [
                pw.Container(
                  padding: const pw.EdgeInsets.symmetric(
                      horizontal: 12, vertical: 8),
                  decoration: pw.BoxDecoration(
                    color: _lightBg(rec.color, 0.10),
                    border: pw.Border.all(
                        color: _lightBorder(rec.color, 0.30), width: 0.5),
                    borderRadius: const pw.BorderRadius.vertical(
                        top: pw.Radius.circular(4)),
                  ),
                  child: pw.Row(children: [
                    pill(rec.priority, rec.color),
                    pw.SizedBox(width: 10),
                    pw.Expanded(
                        child: pw.Text(rec.title,
                            style: ts(10, bold: true))),
                  ]),
                ),
                pw.Padding(
                  padding: const pw.EdgeInsets.all(12),
                  child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(rec.detail,
                            style: ts(8.5, color: textMid, italic: true)),
                        pw.SizedBox(height: 6),
                        pw.Text('Recommended Actions:',
                            style: ts(8, color: textMuted, bold: true)),
                        pw.SizedBox(height: 4),
                        pw.Text(rec.steps,
                            style: ts(8.5, color: textMid, lineSpacing: 3)),
                      ]),
                ),
              ]),
            ))
        .toList();
  }

  Future<String> _getSavePath() async {
    if (defaultTargetPlatform == TargetPlatform.windows) {
      final home = Platform.environment['USERPROFILE'] ?? '';
      if (home.isNotEmpty) return '$home\\Downloads';
    } else if (defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.linux) {
      final home = Platform.environment['HOME'] ?? '';
      if (home.isNotEmpty) return '$home/Downloads';
    }
    final dir = await getApplicationDocumentsDirectory();
    return dir.path;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Report Preview widget
  // ──────────────────────────────────────────────────────────────────────────

  Widget _buildReportPreview(ThemeProvider tp, ThreatMatrixProvider provider) {
    final stats = provider.stats;
    final log = provider.threatLog;
    final now = DateTime.now();
    final total =
        stats.totalThreats + stats.benignFlows + stats.uncertainFlows;
    final threatRate = total > 0
        ? (stats.totalThreats / total * 100).toStringAsFixed(1)
        : '0.0';

    return Container(
      decoration: BoxDecoration(
          color: tp.getCardColor(),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: tp.getBorderColor())),
      child: Column(children: [
        // Header — green-bar + title row
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(children: [
                Container(
                    width: 4,
                    height: 20,
                    decoration: BoxDecoration(
                        color: tp.getSuccessColor(),
                        borderRadius: BorderRadius.circular(2))),
                const SizedBox(width: 10),
                Text('Report Preview',
                    style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: tp.getTextColor(),
                        fontFamily: 'Courier Prime')),
              ]),
              Row(children: [
                _metaRow('Generated', _formatDate(now), tp),
                const SizedBox(width: 20),
                _metaRow('Classification', 'TLP:RED - CONFIDENTIAL', tp,
                    valueColor: tp.getDangerColor()),
              ]),
            ],
          ),
        ),
        Divider(color: tp.getBorderColor(), height: 1),

        // Findings summary bar
        // FIX-1: horizontal padding reduced from 24 → 20 to align with NIST phase indicator/strip styling
        Container(
          padding:
              const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
          decoration: BoxDecoration(
              border:
                  Border(bottom: BorderSide(color: tp.getBorderColor()))),
          child: Row(children: [
            Text('FINDINGS SUMMARY',
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: tp.getTextMutedColor(),
                    letterSpacing: 1.0)),
            const SizedBox(width: 20),
            _severityBadge('CRITICAL',
                stats.exploitCount,
                const Color(0xFFB71C1C), tp),
            const SizedBox(width: 8),
            _severityBadge(
                'HIGH', stats.credAbuseCount, const Color(0xFFE65100), tp),
            const SizedBox(width: 8),
            _severityBadge('MEDIUM', stats.uncertainFlows,
                const Color(0xFFF57F17), tp),
            const SizedBox(width: 8),
            _severityBadge(
                'LOW', stats.benignFlows, const Color(0xFF1B5E20), tp),
            const Spacer(),
            Text('Total Flows: $total',
                style: TextStyle(
                    fontSize: 12,
                    color: tp.getTextMutedColor(),
                    fontFamily: 'Courier Prime')),
            const SizedBox(width: 16),
            Text('Threat Rate: $threatRate%',
                style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: stats.totalThreats > 0
                        ? tp.getDangerColor()
                        : tp.getSuccessColor(),
                    fontFamily: 'Courier Prime')),
          ]),
        ),

        // Body
        Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
            _reportSection('1', 'Training Features — Behavioural Signal Reference', tp),
            const SizedBox(height: 8),
            _trainingFeaturesPreview(tp),
            const SizedBox(height: 28),
            _reportSection('2', 'Executive Summary', tp),
            const SizedBox(height: 12),
            _executiveSummary(tp, stats, log, total, threatRate, provider),
            const SizedBox(height: 28),
            _reportSection('3', 'MITRE ATT\u0026CK Technique Coverage  ·  Correlated Incidents', tp),
            const SizedBox(height: 12),
            // Side-by-side: MITRE (left 45%) + Correlated Incidents (right 55%)
            // This fills the dead space that appeared when only 1-3 MITRE rows were present.
            IntrinsicHeight(
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(flex: 60, child: _mitreSection(tp, stats)),
                  const SizedBox(width: 20),
                  Expanded(flex: 40, child: _incidentSection(tp, provider)),
                ],
              ),
            ),
            const SizedBox(height: 28),
            _reportSection('5', 'Detailed Threat Findings', tp),
            const SizedBox(height: 12),
            _findingsTable(tp, log),
            const SizedBox(height: 28),
            _reportSection('6', 'Recommendations', tp),
            const SizedBox(height: 12),
            _recommendationsSection(tp, stats),
            const SizedBox(height: 24),

            // ── Export bar ────────────────────────────────────────────────
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: BoxDecoration(
                color: tp.isDarkMode
                    ? const Color(0xFF111318).withValues(alpha: 0.6)
                    : const Color(0xFFF8F9FA),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: tp.getBorderColor()),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Text('Export Format',
                      style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: tp.getTextMutedColor(),
                          letterSpacing: 0.5)),
                  const SizedBox(width: 14),
                  Row(
                      children: _formats.map((f) {
                    final sel = _selectedFormat == f.label;
                    return Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: GestureDetector(
                        onTap: () => setState(() => _selectedFormat = f.label),
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 14, vertical: 9),
                          decoration: BoxDecoration(
                            color: sel
                                ? tp.getSuccessColor().withValues(alpha: 0.12)
                                : Colors.transparent,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                                color: sel
                                    ? tp.getSuccessColor()
                                    : tp.getBorderColor()),
                          ),
                          child: Row(mainAxisSize: MainAxisSize.min, children: [
                            Icon(f.icon,
                                size: 14,
                                color: sel
                                    ? tp.getSuccessColor()
                                    : tp.getTextMutedColor()),
                            const SizedBox(width: 6),
                            Text(f.label,
                                style: TextStyle(
                                    fontSize: 13,
                                    fontWeight: sel
                                        ? FontWeight.w600
                                        : FontWeight.w400,
                                    color: sel
                                        ? tp.getSuccessColor()
                                        : tp.getTextMutedColor())),
                          ]),
                        ),
                      ),
                    );
                  }).toList()),
                  const Spacer(),
                  _ReportHoverButton(
                    onPressed: _isGenerating
                        ? null
                        : () => _generateReport(provider, tp),
                    color: tp.getSuccessColor(),
                    textColor:
                        tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                    padding: const EdgeInsets.symmetric(
                        horizontal: 24, vertical: 12),
                    child: Builder(builder: (ctx) {
                      final Color fg = tp.isDarkMode
                          ? const Color(0xFF111318)
                          : Colors.white;
                      return Row(mainAxisSize: MainAxisSize.min, children: [
                        _isGenerating
                            ? SizedBox(
                                width: 14,
                                height: 14,
                                child: CircularProgressIndicator(
                                    strokeWidth: 2, color: fg))
                            : Icon(Icons.download_rounded,
                                size: 16, color: fg),
                        const SizedBox(width: 8),
                        Text(
                            _isGenerating ? 'Saving...' : 'Export & Save',
                            style: TextStyle(
                                fontWeight: FontWeight.w600, color: fg)),
                      ]);
                    }),
                  ),
                ],
              ),
            ),
          ]),
        ),
      ]),
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Section widgets
  // ──────────────────────────────────────────────────────────────────────────

  Widget _metaRow(String label, String value, ThemeProvider tp,
      {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Text('$label: ',
            style:
                TextStyle(fontSize: 11, color: tp.getTextMutedColor())),
        Text(value,
            style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: valueColor ?? tp.getTextSecondaryColor(),
                fontFamily: 'Courier Prime')),
      ]),
    );
  }

  Widget _severityBadge(
      String label, int count, Color color, ThemeProvider tp) {
    return Container(
      padding:
          const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
      decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withValues(alpha: 0.4))),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(
            width: 8,
            height: 8,
            decoration:
                BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: color,
                letterSpacing: 0.5)),
        const SizedBox(width: 6),
        Text(count.toString(),
            style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w800,
                color: color,
                fontFamily: 'Courier Prime')),
      ]),
    );
  }

  static const Map<String, IconData> _sectionIcons = {
    '1': Icons.summarize_rounded,
    '2': Icons.security_rounded,
    '3': Icons.hub_rounded,
    '4': Icons.manage_search_rounded,
    '5': Icons.tips_and_updates_rounded,
  };

  Widget _reportSection(String number, String title, ThemeProvider tp) {
    final icon = _sectionIcons[number] ?? Icons.circle;
    return Row(children: [
      Container(
        width: 30, height: 30,
        decoration: BoxDecoration(
            color: tp.getSuccessColor(),
            borderRadius: BorderRadius.circular(8)),
        child: Center(child: Icon(icon, size: 16,
            color: tp.isDarkMode ? const Color(0xFF111318) : Colors.white)),
      ),
      const SizedBox(width: 10),
      Text(title,
          style: TextStyle(
              fontSize: 15, fontWeight: FontWeight.w700,
              color: tp.getTextColor(), fontFamily: 'Courier Prime')),
      const SizedBox(width: 12),
      Expanded(child: Divider(color: tp.getBorderColor())),
    ]);
  }

  Widget _trainingFeaturesPreview(ThemeProvider tp) {
    final green = tp.getSuccessColor();
    final rows = [
      ['flow_duration',            'Flow Volume',  'Scan flows are extremely brief; brute-force spans a longer window.'],
      ['fwd_pkts_tot / bwd_pkts_tot', 'Flow Volume', 'Attackers send high-volume small packets; closed ports return nothing.'],
      ['flow_pkts_per_sec',        'Rate',         'Automated tools produce packet rates no human would generate.'],
      ['payload_bytes_per_second', 'Rate',         'Injection carries dense payloads; reconnaissance carries almost none.'],
      ['down_up_ratio',            'Asymmetry',    'Attack traffic is heavily client-skewed, keeping this ratio low.'],
      ['flow_SYN_flag_count',      'TCP Flags',    'A SYN flood with no ACK is the textbook signature of port scanning.'],
      ['flow_RST_flag_count',      'TCP Flags',    'High RST counts reflect probes rejected by closed or filtered ports.'],
    ];
    return Container(
      decoration: BoxDecoration(
        color: green.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: green.withValues(alpha: 0.20)),
      ),
      child: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 10, 14, 6),
          child: Text(
            'ThreatMatrix classifies threats from 16 flow-level behavioural statistics — '
            'no packet payload inspection. The model is protocol-agnostic and resilient to tool variation.',
            style: TextStyle(fontSize: 12, color: tp.getTextSecondaryColor(), height: 1.5),
          ),
        ),
        Divider(color: tp.getBorderColor(), height: 1),
        // Header row
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
          child: Row(children: [
            Expanded(flex: 4, child: Text('Feature', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: tp.getTextMutedColor()))),
            Expanded(flex: 2, child: Text('Group', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: tp.getTextMutedColor()))),
            Expanded(flex: 6, child: Text('Behavioural Significance', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: tp.getTextMutedColor()))),
          ]),
        ),
        ...rows.asMap().entries.map((e) {
          final isAlt = e.key.isOdd;
          final f = e.value;
          return Container(
            color: isAlt
                ? (tp.isDarkMode ? Colors.white.withValues(alpha: 0.03) : Colors.black.withValues(alpha: 0.02))
                : Colors.transparent,
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Expanded(flex: 4, child: Text(f[0], style: TextStyle(fontSize: 11, color: tp.getTextColor(), fontFamily: 'Courier Prime'))),
              Expanded(flex: 2, child: Text(f[1], style: TextStyle(fontSize: 11, color: green))),
              Expanded(flex: 6, child: Text(f[2], style: TextStyle(fontSize: 11, color: tp.getTextSecondaryColor(), height: 1.4))),
            ]),
          );
        }),
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 6, 14, 10),
          child: Text(
            'Full 16-feature reference is on page 1 of the exported PDF.',
            style: TextStyle(fontSize: 11, color: tp.getTextMutedColor(), fontStyle: FontStyle.italic),
          ),
        ),
      ]),
    );
  }


  Widget _executiveSummary(ThemeProvider tp, DashboardStats stats,
      List<ThreatEntry> log, int total, String threatRate,
      ThreatMatrixProvider provider) {
    final narrative = stats.totalThreats == 0
    ? 'No confirmed threat events were detected during the selected monitoring period. '
        'Current risk score is ${provider.riskScore.toStringAsFixed(0)}/100 (${provider.riskLabel}). '
        'Immediate analyst review recommended for all Active events.'
    : 'A total of ${stats.totalThreats} threat events were detected during the selected monitoring period. '
        'Current risk score is ${provider.riskScore.toStringAsFixed(0)}/100 (${provider.riskLabel}). '
        'Analyst review in progress.';

    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        _kpiBox('Threats', stats.totalThreats.toString(),
            stats.totalThreats > 0
                ? const Color(0xFFB71C1C)
                : tp.getSuccessColor(),
            tp),
        const SizedBox(width: 12),
        _kpiBox('Benign', stats.benignFlows.toString(),
            tp.getSuccessColor(), tp),
        const SizedBox(width: 12),
        _kpiBox('Uncertain', stats.uncertainFlows.toString(),
            const Color(0xFFF57F17), tp),
        const SizedBox(width: 12),
        _kpiBox(
            'Risk Score',
            '${provider.riskScore.toStringAsFixed(0)}/100',
            provider.riskScore >= 50
                ? const Color(0xFFB71C1C)
                : tp.getSuccessColor(),
            tp),
        const SizedBox(width: 12),
        _kpiBox(
            'Confidence',
            stats.modelAccuracy > 0
                ? '${stats.modelAccuracy.toStringAsFixed(1)}%'
                : '--',
            tp.getSuccessColor(),
            tp),
      ]),
      const SizedBox(height: 14),
      Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
            color: tp.isDarkMode
                ? const Color(0xFF111318)
                : const Color(0xFFF8F9FA),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: tp.getBorderColor())),
        child: Text(narrative,
            style: TextStyle(
                fontSize: 13,
                color: tp.getTextSecondaryColor(),
                height: 1.7)),
      ),
    ]);
  }

  Widget _kpiBox(
      String label, String value, Color color, ThemeProvider tp) {
    return Expanded(
        child: Container(
      padding:
          const EdgeInsets.symmetric(vertical: 12, horizontal: 14),
      decoration: BoxDecoration(
          color: color.withValues(alpha: 0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.2))),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(value,
            style: TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.w800,
                color: color,
                fontFamily: 'Courier Prime')),
        Text(label,
            style:
                TextStyle(fontSize: 11, color: tp.getTextMutedColor())),
      ]),
    ));
  }

  Widget _mitreSection(ThemeProvider tp, DashboardStats stats) {
    final techniques = [
      if (stats.reconCount > 0)
        _MitreTechnique('T1595.001', 'Active Scanning: Scanning IP Blocks', 'TA0043 Reconnaissance',
            stats.reconCount, 'Critical', const Color(0xFFB71C1C)),
      if (stats.credAbuseCount > 0)
        _MitreTechnique('T1110', 'Brute Force: Password Guessing', 'TA0006 Credential Access',
            stats.credAbuseCount, 'High', const Color(0xFFE65100)),
      if (stats.exploitCount > 0)
        _MitreTechnique(
            'T1190',
            'Exploit Public-Facing Application',
            'TA0001 Initial Access',
            stats.exploitCount,
            'Critical',
            const Color(0xFFB71C1C)),
      if (stats.novelCount > 0)
        _MitreTechnique(
            'T0000',
            'Unknown / Novel — Unseen During Training',
            'Phase 3 OSR',
            stats.novelCount,
            'Critical',
            const Color(0xFF6A1B9A)),
    ];
    if (techniques.isEmpty) {
      return _emptyState(
          'No MITRE techniques triggered in this period.', tp);
    }

    return Column(children: [
      Container(
        padding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
        decoration: BoxDecoration(
            color: tp.isDarkMode
                ? const Color(0xFF111318)
                : const Color(0xFFF0F0F0),
            borderRadius:
                const BorderRadius.vertical(top: Radius.circular(8)),
            border: Border.all(color: tp.getBorderColor())),
        child: Row(children: [
          Expanded(flex: 2, child: _th('Technique ID', tp, center: false)),
          Expanded(flex: 3, child: _th('Technique Name', tp, center: false)),
          Expanded(flex: 3, child: _th('Tactic', tp, center: false)),
          Expanded(flex: 1, child: _th('Count', tp, center: false)),
          Expanded(flex: 2, child: _th('Severity', tp, center: false)),
        ]),
      ),
      Container(
        decoration: BoxDecoration(
            border: Border(
                left: BorderSide(color: tp.getBorderColor()),
                right: BorderSide(color: tp.getBorderColor()),
                bottom: BorderSide(color: tp.getBorderColor())),
            borderRadius:
                const BorderRadius.vertical(bottom: Radius.circular(8))),
        child: Column(
            children: techniques.asMap().entries.map((e) {
          final t = e.value;
          return Container(
            padding: const EdgeInsets.symmetric(
                horizontal: 16, vertical: 11),
            decoration: BoxDecoration(
              color: e.key % 2 == 0
                  ? Colors.transparent
                  : (tp.isDarkMode
                      ? Colors.white.withValues(alpha: 0.02)
                      : Colors.black.withValues(alpha: 0.015)),
              border: Border(
                  bottom: e.key < techniques.length - 1
                      ? BorderSide(color: tp.getBorderColor())
                      : BorderSide.none),
            ),
            child: Row(children: [
              Expanded(
                  flex: 2,
                  child: Text(t.id,
                      style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                          color: tp.isDarkMode
                              ? const Color(0xFF42A5F5)
                              : const Color(0xFF1565C0),
                          fontFamily: 'Courier Prime'))),
              Expanded(
                  flex: 3,
                  child: Text(t.name,
                      style:
                          TextStyle(fontSize: 12, color: tp.getTextColor()))),
              Expanded(
                  flex: 3,
                  child: Text(t.tactic,
                      style: TextStyle(
                          fontSize: 12,
                          color: tp.getTextSecondaryColor()))),
              Expanded(
                  flex: 1,
                  child: Text(t.count.toString(),
                      style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                          color: t.color,
                          fontFamily: 'Courier Prime'))),
              Expanded(
                  flex: 2,
                  child: Align(
                      alignment: Alignment.centerLeft,
                      child: _compactPill(t.severity, t.color))),
            ]),
          );
        }).toList()),
      ),
    ]);
  }

  Widget _incidentSection(ThemeProvider tp, ThreatMatrixProvider provider) {
    final incidents = provider.incidents;
    if (incidents.isEmpty) {
      return _emptyState(
          'No correlated incidents in this period.', tp);
    }
    return Column(
        children: incidents.take(10).map((inc) {
      final color = inc.severity == 'Critical'
          ? const Color(0xFFB71C1C)
          : inc.severity == 'High'
              ? const Color(0xFFE65100)
              : const Color(0xFFF57F17);
      return Container(
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: tp.getBorderColor())),
        child: Row(children: [
          Container(
              width: 5,
              height: 56,
              decoration: BoxDecoration(
                  color: color,
                  borderRadius: const BorderRadius.horizontal(
                      left: Radius.circular(8)))),
          Padding(
            padding: const EdgeInsets.symmetric(
                horizontal: 14, vertical: 10),
            child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
              Row(children: [
                Text(inc.incidentId,
                    style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                        color: tp.getTextColor(),
                        fontFamily: 'Courier Prime')),
                const SizedBox(width: 10),
                _compactPill(inc.severity, color),
              ]),
              const SizedBox(height: 3),
              Text(inc.description,
                  style: TextStyle(
                      fontSize: 12,
                      color: tp.getTextSecondaryColor())),
              Text(
                  '${_formatTime(inc.firstSeen)} - ${_formatTime(inc.lastSeen)}',
                  style: TextStyle(
                      fontSize: 11,
                      color: tp.getTextMutedColor(),
                      fontFamily: 'Courier Prime')),
            ]),
          ),
          const Spacer(),
          Padding(
              padding: const EdgeInsets.only(right: 16),
              child: Text(
                  '${inc.count} event${inc.count > 1 ? "s" : ""}',
                  style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: color,
                      fontFamily: 'Courier Prime'))),
        ]),
      );
    }).toList());
  }

  Widget _findingsTable(ThemeProvider tp, List<ThreatEntry> log) {
    if (log.isEmpty) {
      return _emptyState(
          'No threat findings recorded in this period.', tp);
    }

    const cols = [
      ('ID', 2),
      ('Timestamp', 3),
      ('Origin IP', 2),
      ('Destination IP', 2),
      ('MITRE', 2),
      ('Severity', 3),
      ('Confidence', 2),
      ('Kill Chain', 3),
      ('Key Signals', 4)
    ];

    // Typical behavioural signals per attack type — shown in preview (plain text, no icons).
    // Exported PDF shows live SHAP top 3 for all non-UNKNOWN threats.
    String previewSignals(ThreatEntry entry) {
      if (entry.isNovel || entry.type == 'UNKNOWN') return 'Novel / out-of-distribution pattern';
      final t = entry.type.toLowerCase();
      if (t.contains('scan') || t.contains('recon'))  return 'Packet rate (high)  ·  Payload (low)  ·  SYN flags (high)';
      if (t.contains('brute') || t.contains('cred'))  return 'Flow duration (short)  ·  DL/UL ratio (low)  ·  FIN flags (high)';
      if (t.contains('sql') || t.contains('exploit')) return 'Fwd data pkts (high)  ·  Payload (high)  ·  Bwd pkts (low)';
      return 'Anomalous flow profile';
    }

    return Column(children: [
      Container(
        padding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
        decoration: BoxDecoration(
            color: tp.isDarkMode
                ? const Color(0xFF111318)
                : const Color(0xFFF0F0F0),
            borderRadius:
                const BorderRadius.vertical(top: Radius.circular(8)),
            border: Border.all(color: tp.getBorderColor())),
        child: Row(
            children: cols
                .map((c) =>
                    Expanded(flex: c.$2, child: _th(c.$1, tp, center: false)))
                .toList()),
      ),
      Container(
        decoration: BoxDecoration(
            border: Border(
                left: BorderSide(color: tp.getBorderColor()),
                right: BorderSide(color: tp.getBorderColor()),
                bottom: BorderSide(color: tp.getBorderColor())),
            borderRadius:
                const BorderRadius.vertical(bottom: Radius.circular(8))),
        child: Column(
            children: log
                .take(50)
                .toList()
                .asMap()
                .entries
                .map((e) {
          final entry = e.value;
          final sevColor = entry.severity == 'Critical'
              ? const Color(0xFFB71C1C)
              : entry.severity == 'High'
                  ? const Color(0xFFE65100)
                  : entry.severity == 'Medium'
                      ? const Color(0xFFF57F17)
                      : const Color(0xFF1B5E20);

          return Container(
            padding: const EdgeInsets.symmetric(
                horizontal: 16, vertical: 9),
            decoration: BoxDecoration(
              color: e.key % 2 == 0
                  ? Colors.transparent
                  : (tp.isDarkMode
                      ? Colors.white.withValues(alpha: 0.02)
                      : Colors.black.withValues(alpha: 0.015)),
              border: Border(
                  bottom: e.key < log.length - 1 && e.key < 49
                      ? BorderSide(color: tp.getBorderColor())
                      : BorderSide.none),
            ),
            child: Row(children: [
              Expanded(
                  flex: 2,
                  child: Text(entry.id,
                      style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: tp.getSuccessColor(),
                          fontFamily: 'Courier Prime'))),
              Expanded(
                  flex: 3,
                  child: Text(entry.formattedTimestamp,
                      style: TextStyle(
                          fontSize: 11,
                          color: tp.getTextSecondaryColor()))),
              Expanded(
                  flex: 2,
                  child: Text(entry.originIp ?? '--',
                      style: TextStyle(
                          fontSize: 11, color: tp.getTextColor()),
                      overflow: TextOverflow.ellipsis)),
              Expanded(
                  flex: 2,
                  child: Text(entry.destinationIp ?? '--',
                      style: TextStyle(
                          fontSize: 11, color: tp.getTextColor()),
                      overflow: TextOverflow.ellipsis)),
              Expanded(
                  flex: 2,
                  child: Text(
                      entry.mitreInfo?.techniqueId ?? '--',
                      style: TextStyle(
                          fontSize: 11,
                          color: tp.isDarkMode
                              ? const Color(0xFF42A5F5)
                              : const Color(0xFF1565C0),
                          fontFamily: 'Courier Prime'))),
              Expanded(
                  flex: 3,
                  child: Align(
                      alignment: Alignment.centerLeft,
                      child: _compactPill(entry.severity, sevColor))),
              Expanded(
                  flex: 2,
                  child: Text(
                    entry.modelConfidence != null
                        ? '${(entry.modelConfidence! * 100).toStringAsFixed(1)}%'
                        : entry.attackProbability != null
                            ? '${(entry.attackProbability! * 100).toStringAsFixed(1)}%'
                            : '--',
                    style: TextStyle(
                        fontSize: 11,
                        color: tp.getTextSecondaryColor(),
                        fontFamily: 'Courier Prime'),
                  )),
              Expanded(
                  flex: 3,
                  child: Text(entry.killChainPhase ?? '--',
                      style: TextStyle(
                          fontSize: 11,
                          color: tp.getTextSecondaryColor()),
                      overflow: TextOverflow.ellipsis)),
              Expanded(
                  flex: 4,
                  child: Text(previewSignals(entry),
                      style: TextStyle(
                          fontSize: 10,
                          color: tp.getTextMutedColor(),
                          fontFamily: 'Courier Prime'),
                      overflow: TextOverflow.ellipsis)),
            ]),
          );
        }).toList()),
      ),
      if (log.length > 50)
        Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(
                '${log.length - 50} additional entries omitted — full dataset exported to file.',
                style: TextStyle(
                    fontSize: 11,
                    color: tp.getTextMutedColor(),
                    fontStyle: FontStyle.italic))),
      const SizedBox(height: 6),
      Text(
        'Key signals show typical behavioural features for each attack class. '
        'Exported PDF includes live per-flow SHAP top 3 signals for all known threats.',
        style: TextStyle(fontSize: 11, color: tp.getTextMutedColor(), fontStyle: FontStyle.italic),
      ),
    ]);
  }

  Widget _recommendationsSection(
      ThemeProvider tp, DashboardStats stats) {
    final recs = <({
      String priority,
      Color color,
      String title,
      String detail,
      String steps
    })>[];
    if (stats.reconCount > 0) {
      recs.add((
        priority: 'CRITICAL',
        color: const Color(0xFFB71C1C),
        title: 'Investigate Reconnaissance Activity',
        detail:
            'T1046/T1595.001 - Network scanning detected. Monitor for follow-on activity.',
        steps:
            '1. Log and monitor source IPs\n2. Update IDS/IPS signatures for scanning patterns\n3. Review exposed services and close unnecessary ports\n4. Correlate with subsequent attack activity\n5. Document source IPs for incident correlation'
      ));
    }
    if (stats.exploitCount > 0) {
      recs.add((
        priority: 'CRITICAL',
        color: const Color(0xFFB71C1C),
        title: 'Remediate Active Exploitation Attempt',
        detail:
            'T1190 - SQL injection via HTTP/HTTPS detected. Potential data breach risk.',
        steps:
            '1. Block the source IP at the network boundary and review web application firewall rules if available\n2. Audit application logs for successful exploitation indicators\n3. Engage the development team for an emergency patch\n4. Isolate the affected host until remediation is confirmed'
      ));
    }
    if (stats.credAbuseCount > 0) {
      recs.add((
        priority: 'HIGH',
        color: const Color(0xFFE65100),
        title: 'Harden Authentication Controls',
        detail: 'T1110 - Credential abuse attacks detected (HTTP/HTTPS brute force).',
        steps:
            '1. Enforce account lockout after repeated failed attempts\n2. Enable MFA on all administrative and privileged accounts\n3. Audit authentication logs for successful follow-on access\n4. Configure login rate limiting on authentication services\n5. Rotate credentials for targeted accounts'
      ));
    }
    if (stats.uncertainFlows > 0) {
      recs.add((
        priority: 'MEDIUM',
        color: const Color(0xFFF57F17),
        title: 'Investigate Anomalous Flows',
        detail:
            '${stats.uncertainFlows} UNCERTAIN flows flagged for Phase 3 open-set classifier review.',
        steps:
            '1. Capture full packet data (PCAP) from the flagged source IP for further inspection\n2. Review the Phase 1 detection sensitivity in ThreatMatrix settings if false positives are suspected\n3. Seek expert review if Phase 3 classifies the flow as UNKNOWN\n4. Document findings for future model evaluation'
      ));
    }
    if (recs.isEmpty) {
      recs.add((
        priority: 'INFO',
        color: const Color(0xFF1B5E20),
        title: 'Maintain Monitoring Posture',
        detail: 'No active threats detected. System operating normally.',
        steps:
            '1. Continue live flow monitoring\n2. Review ThreatMatrix detection logs periodically to confirm normal baseline\n3. Review detection thresholds quarterly\n4. Schedule next threat assessment in 30 days'
      ));
    }

    return Column(
        children: recs
            .map((rec) => Container(
                  margin: const EdgeInsets.only(bottom: 12),
                  decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                          color: rec.color.withValues(alpha: 0.3))),
                  child: Column(children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 16, vertical: 10),
                      decoration: BoxDecoration(
                          color: rec.color.withValues(alpha: 0.08),
                          borderRadius: const BorderRadius.vertical(
                              top: Radius.circular(8)),
                          border: Border(
                              bottom: BorderSide(
                                  color:
                                      rec.color.withValues(alpha: 0.2)))),
                      child: Row(children: [
                        _compactPill(rec.priority, rec.color),
                        const SizedBox(width: 12),
                        Expanded(
                            child: Text(rec.title,
                                style: TextStyle(
                                    fontSize: 13,
                                    fontWeight: FontWeight.w700,
                                    color: tp.getTextColor()))),
                      ]),
                    ),
                    Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                            crossAxisAlignment:
                                CrossAxisAlignment.start,
                            children: [
                          Text(rec.detail,
                              style: TextStyle(
                                  fontSize: 12,
                                  color: tp.getTextSecondaryColor(),
                                  fontStyle: FontStyle.italic)),
                          const SizedBox(height: 10),
                          Text('Recommended Actions:',
                              style: TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.w700,
                                  color: tp.getTextMutedColor(),
                                  letterSpacing: 0.4)),
                          const SizedBox(height: 6),
                          Text(rec.steps,
                              style: TextStyle(
                                  fontSize: 12,
                                  color: tp.getTextSecondaryColor(),
                                  height: 1.8,
                                  fontFamily: 'Courier Prime')),
                        ])),
                  ]),
                ))
            .toList());
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Shared micro-widgets
  // ──────────────────────────────────────────────────────────────────────────

  Widget _th(String label, ThemeProvider tp, {bool center = true}) => Text(label,
      textAlign: center ? TextAlign.center : TextAlign.left,
      style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w600,
          color: tp.getTextMutedColor(),
          letterSpacing: 0.4));

  Widget _compactPill(String label, Color color) {
    return Container(
      padding:
          const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(label,
          style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: color,
              letterSpacing: 0.3)),
    );
  }

  Widget _emptyState(String message, ThemeProvider tp) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
          color: tp.isDarkMode
              ? const Color(0xFF111318)
              : const Color(0xFFF8F9FA),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: tp.getBorderColor())),
      child: Center(
          child: Text(message,
              style: TextStyle(
                  fontSize: 13, color: tp.getTextMutedColor()))),
    );
  }

  ThemeProvider get tp =>
      Provider.of<ThemeProvider>(context, listen: false);

  // ──────────────────────────────────────────────────────────────────────────
  // Report content builders — CSV + JSON
  // ──────────────────────────────────────────────────────────────────────────

  Map<String, dynamic> _buildReportJson(ThreatMatrixProvider provider) {
    final stats = provider.stats;
    final now = DateTime.now();
    return {
      'report_metadata': {
        'title': 'ThreatMatrix Network Threat Behaviour Analysis Report',
        'generated_at': now.toIso8601String(),
        'reporting_period': 'All Available Data',
        'classification': 'TLP:RED - CONFIDENTIAL',
        'generator': 'ThreatMatrix'
      },
      'executive_summary': {
        'total_flows':
            stats.totalThreats + stats.benignFlows + stats.uncertainFlows,
        'threats_detected': stats.totalThreats,
        'benign_flows': stats.benignFlows,
        'uncertain_flows': stats.uncertainFlows,
        'model_confidence_pct': stats.modelAccuracy.toStringAsFixed(2),
        'risk_score': provider.riskScore.toStringAsFixed(1),
        'risk_label': provider.riskLabel
      },
      'attack_breakdown': {
        'reconnaissance_t1046': stats.reconCount,
        'credential_abuse_t1110': stats.credAbuseCount,
        'active_exploitation_t1190': stats.exploitCount
      },
      'mitre_techniques': [
        if (stats.reconCount > 0)
          {
            'id': 'T1046 / T1595.001',
            'name': 'Network Service Discovery / Scanning IP Blocks',
            'tactic': 'TA0043 Reconnaissance',
            'count': stats.reconCount,
            'severity': 'Low'
          },
        if (stats.credAbuseCount > 0)
          {
            'id': 'T1110.001 / T1110.003',
            'name': 'Password Guessing / Password Spraying',
            'tactic': 'TA0006 Credential Access',
            'count': stats.credAbuseCount,
            'severity': 'High'
          },
        if (stats.exploitCount > 0)
          {
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access',
            'count': stats.exploitCount,
            'severity': 'Critical'
          },
      ],
      'incidents': provider.incidents
          .map((inc) => {
                'id': inc.incidentId,
                'dominant_type': inc.dominantType,
                'severity': inc.severity,
                'event_count': inc.count,
                'first_seen': inc.firstSeen.toIso8601String(),
                'last_seen': inc.lastSeen.toIso8601String()
              })
          .toList(),
      'threat_log': provider.threatLog
          .map((e) => {
                'id': e.id,
                'timestamp': e.timestamp.toIso8601String(),
                'type': e.type,
                'severity': e.severity,
                'status': e.status,
                'mitre_id': e.mitreInfo?.techniqueId,
                'mitre_technique': e.mitreInfo?.techniqueName,
                'mitre_tactic': e.mitreInfo?.tactic,
                'kill_chain_phase': e.killChainPhase,
                'attack_probability': e.attackProbability,
                'model_confidence': e.modelConfidence,
                'recommended_action': e.recommendedAction
              })
          .toList(),
    };
  }

  String _buildCsv(List<ThreatEntry> log) {
    final buf = StringBuffer();
    buf.writeln(
        'ID,Timestamp,Type,Severity,Status,MITRE_ID,MITRE_Technique,MITRE_Tactic,Kill_Chain_Phase,Attack_Probability,Model_Confidence,Recommended_Action');
    for (final e in log) {
      buf.writeln([
        e.id,
        e.timestamp.toIso8601String(),
        '"${e.type}"',
        e.severity,
        e.status,
        e.mitreInfo?.techniqueId ?? '',
        '"${e.mitreInfo?.techniqueName ?? ''}"',
        '"${e.mitreInfo?.tactic ?? ''}"',
        '"${e.killChainPhase ?? ''}"',
        e.attackProbability?.toStringAsFixed(6) ?? '',
        e.modelConfidence?.toStringAsFixed(6) ?? '',
        '"${(e.recommendedAction ?? '').replaceAll('"', '""')}"'
      ].join(','));
    }
    return buf.toString();
  }

  String _buildPlainTextReport(ThreatMatrixProvider provider) {
    final stats = provider.stats;
    final buf = StringBuffer();
    final total =
        stats.totalThreats + stats.benignFlows + stats.uncertainFlows;
    buf.writeln('=' * 70);
    buf.writeln('  THREATMATRIX - NETWORK THREAT BEHAVIOURAL ANALYSIS REPORT');
    buf.writeln('  CONFIDENTIAL - TLP:RED');
    buf.writeln('=' * 70);
    buf.writeln('Generated  : ${DateTime.now()}');
    buf.writeln('Period     : All Available Data');
    buf.writeln('Generator  : ThreatMatrix v2.0');
    buf.writeln('');
    buf.writeln('-' * 70);
    buf.writeln('1. EXECUTIVE SUMMARY');
    buf.writeln('-' * 70);
    buf.writeln('Total Flows Analysed : $total');
    buf.writeln('Threats Detected     : ${stats.totalThreats}');
    buf.writeln('Benign Flows         : ${stats.benignFlows}');
    buf.writeln('Uncertain Flows      : ${stats.uncertainFlows}');
    buf.writeln(
        'Model Confidence     : ${stats.modelAccuracy.toStringAsFixed(1)}%');
    buf.writeln(
        'Risk Score           : ${provider.riskScore.toStringAsFixed(0)} / 100 (${provider.riskLabel})');
    buf.writeln('');
    buf.writeln('-' * 70);
    buf.writeln('2. MITRE ATT&CK TECHNIQUES OBSERVED');
    buf.writeln('-' * 70);
    if (stats.reconCount > 0) {
      buf.writeln(
          '  T1046  Network Service Discovery      TA0043 Recon.       ${stats.reconCount} events');
    }
    if (stats.credAbuseCount > 0) {
      buf.writeln(
          '  T1110  Password Guessing/Spraying      TA0006 Cred.Access  ${stats.credAbuseCount} events');
    }
    if (stats.exploitCount > 0) {
      buf.writeln(
          '  T1190  SQL Injection (HTTP/HTTPS)        TA0001 Init.Access  ${stats.exploitCount} events');
    }
    if (stats.totalThreats == 0) {
      buf.writeln('  No MITRE techniques triggered.');
    }
    buf.writeln('');
    buf.writeln('-' * 70);
    buf.writeln('3. THREAT LOG (first 200 entries)');
    buf.writeln('-' * 70);
    buf.writeln(
        '${"ID".padRight(12)}${"Timestamp".padRight(24)}${"Origin IP".padRight(16)}${"Destination IP".padRight(16)}${"Severity".padRight(12)}${"MITRE".padRight(10)}Confidence');
    buf.writeln('-' * 70);
    for (final e in provider.threatLog.take(200)) {
      final conf = e.modelConfidence != null
          ? '${(e.modelConfidence! * 100).toStringAsFixed(1)}%'
          : e.attackProbability != null
              ? '${(e.attackProbability! * 100).toStringAsFixed(1)}%'
              : '-';
      buf.writeln(
          '${e.id.padRight(12)}${e.formattedTimestamp.padRight(24)}${e.type.padRight(16)}${e.severity.padRight(12)}${(e.mitreInfo?.techniqueId ?? '-').padRight(10)}$conf');
    }
    buf.writeln('');
    buf.writeln('=' * 70);
    buf.writeln('  END OF REPORT - ThreatMatrix');
    buf.writeln('=' * 70);
    return buf.toString();
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────────────────────────────────

  String _formatDate(DateTime t) =>
      '${t.day.toString().padLeft(2, '0')}/${t.month.toString().padLeft(2, '0')}/${t.year} ${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';

  String _formatTime(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';
}

// ──────────────────────────────────────────────────────────────────────────────
// Preview Dialog — only shown for CSV and JSON
// ──────────────────────────────────────────────────────────────────────────────

class _PreviewDialog extends StatelessWidget {
  final String filename;
  final String content;
  final String format;
  final ThemeProvider tp;
  const _PreviewDialog(
      {required this.filename,
      required this.content,
      required this.format,
      required this.tp});

  @override
  Widget build(BuildContext context) {
    final lines = content.split('\n');
    final previewLines = lines.take(80).join('\n');
    final isTruncated = lines.length > 80;
    final formatColor = format == 'CSV'
        ? const Color(0xFF1B5E20)
        : (tp.isDarkMode
            ? const Color(0xFF42A5F5)
            : const Color(0xFF1565C0));

    return Dialog(
      backgroundColor: tp.getCardColor(),
      shape:
          RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      insetPadding:
          const EdgeInsets.symmetric(horizontal: 48, vertical: 36),
      child: SizedBox(
          width: 900,
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            // Header
            Container(
              padding: const EdgeInsets.symmetric(
                  horizontal: 24, vertical: 16),
              decoration: BoxDecoration(
                  color: tp.isDarkMode
                      ? const Color(0xFF111318)
                      : const Color(0xFFF0F4F8),
                  borderRadius: const BorderRadius.vertical(
                      top: Radius.circular(12)),
                  border: Border(
                      bottom:
                          BorderSide(color: tp.getBorderColor()))),
              child: Row(children: [
                Icon(Icons.preview_outlined,
                    color: tp.getSuccessColor(), size: 20),
                const SizedBox(width: 10),
                Expanded(
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                      Text('Report Preview',
                          style: TextStyle(
                              fontSize: 15,
                              fontWeight: FontWeight.bold,
                              color: tp.getTextColor(),
                              fontFamily: 'Courier Prime')),
                      const SizedBox(height: 1),
                      Text(filename,
                          style: TextStyle(
                              fontSize: 11,
                              color: tp.getTextMutedColor(),
                              fontFamily: 'Courier Prime'),
                          overflow: TextOverflow.ellipsis),
                    ])),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                      color: formatColor.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(
                          color: formatColor.withValues(alpha: 0.3))),
                  child: Text(format,
                      style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: formatColor)),
                ),
                const SizedBox(width: 12),
                IconButton(
                    onPressed: () => Navigator.pop(context, false),
                    icon: Icon(Icons.close,
                        color: tp.getTextMutedColor(), size: 18),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints()),
              ]),
            ),
            // Content
            Container(
              height: 400,
              decoration: BoxDecoration(
                  color: tp.isDarkMode
                      ? const Color(0xFF080C10)
                      : const Color(0xFFF8F9FA)),
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                if (isTruncated)
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 16, vertical: 8),
                    decoration: BoxDecoration(
                        color: tp
                            .getWarningColor()
                            .withValues(alpha: 0.07),
                        border: Border(
                            bottom: BorderSide(
                                color: tp
                                    .getWarningColor()
                                    .withValues(alpha: 0.2)))),
                    child: Row(children: [
                      Icon(Icons.info_outline,
                          size: 13, color: tp.getWarningColor()),
                      const SizedBox(width: 6),
                      Text(
                          'Showing first 80 of ${lines.length} lines - full content will be saved to file.',
                          style: TextStyle(
                              fontSize: 11,
                              color: tp.getWarningColor())),
                    ]),
                  ),
                Expanded(
                    child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Text(previewLines,
                      style: TextStyle(
                          fontSize: 12,
                          color: tp.getTextSecondaryColor(),
                          fontFamily: 'Courier Prime',
                          height: 1.6)),
                )),
              ]),
            ),
            // Footer
            Container(
              padding: const EdgeInsets.symmetric(
                  horizontal: 24, vertical: 16),
              decoration: BoxDecoration(
                  color: tp.isDarkMode
                      ? const Color(0xFF111318).withValues(alpha: 0.6)
                      : const Color(0xFFF5F7FA),
                  borderRadius: const BorderRadius.vertical(
                      bottom: Radius.circular(12)),
                  border: Border(
                      top: BorderSide(color: tp.getBorderColor()))),
              child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                Row(children: [
                  Icon(Icons.save_alt_outlined,
                      size: 14, color: tp.getTextMutedColor()),
                  const SizedBox(width: 6),
                  Text(
                      kIsWeb
                          ? 'File will be downloaded to your browser Downloads folder.'
                          : 'File will be saved to your Downloads folder.',
                      style: TextStyle(
                          fontSize: 12,
                          color: tp.getTextMutedColor())),
                ]),
                Row(children: [
                  _ReportHoverButton(
                    onPressed: () => Navigator.pop(context, false),
                    color: tp.getBorderColor(),
                    textColor: tp.getTextMutedColor(),
                    outlined: true,
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                    child: const Text('Cancel', style: TextStyle(fontWeight: FontWeight.w500)),
                  ),
                  const SizedBox(width: 12),
                  _ReportHoverButton(
                    onPressed: () => Navigator.pop(context, true),
                    color: tp.getSuccessColor(),
                    textColor: tp.isDarkMode ? const Color(0xFF111318) : Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                    child: Row(mainAxisSize: MainAxisSize.min, children: [
                      Icon(Icons.download_rounded, size: 16,
                          color: tp.isDarkMode ? const Color(0xFF111318) : Colors.white),
                      const SizedBox(width: 6),
                      Text('Confirm & Download',
                          style: TextStyle(
                              fontWeight: FontWeight.w600,
                              color: tp.isDarkMode ? const Color(0xFF111318) : Colors.white)),
                    ]),
                  ),
                ]),
              ]),
            ),
          ])),
    );
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Modern Dropdown (reports-local)
// ──────────────────────────────────────────────────────────────────────────────

// _ReportModernDropdown removed — replaced by shared TmModernDropdown (tm_dropdown.dart)

// ──────────────────────────────────────────────────────────────────────────────
// TM Icon Button — ghost-style action button for tables/toolbars
// Design: transparent rest state → colored pill on hover + border bloom + scale
// Inspired by CrowdStrike Falcon & Datadog Security dashboards
// ──────────────────────────────────────────────────────────────────────────────

class _TmIconButton extends StatefulWidget {
  final IconData icon;
  final Color color;
  final String tooltip;
  final VoidCallback onTap;

  const _TmIconButton({
    required this.icon,
    required this.color,
    required this.tooltip,
    required this.onTap,
  });

  @override
  State<_TmIconButton> createState() => _TmIconButtonState();
}

class _TmIconButtonState extends State<_TmIconButton> {
  bool _hovered = false;
  bool _pressed = false;

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: widget.tooltip,
      waitDuration: const Duration(milliseconds: 400),
      decoration: BoxDecoration(
        color: widget.color.withValues(alpha: 0.90),
        borderRadius: BorderRadius.circular(5),
      ),
      textStyle: const TextStyle(
          color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600),
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => _hovered = true),
        onExit: (_) => setState(() { _hovered = false; _pressed = false; }),
        child: GestureDetector(
          onTapDown: (_) => setState(() => _pressed = true),
          onTapUp:   (_) => setState(() => _pressed = false),
          onTapCancel: ()  => setState(() => _pressed = false),
          onTap: widget.onTap,
          child: AnimatedScale(
            scale: _pressed ? 0.90 : (_hovered ? 1.08 : 1.0),
            duration: const Duration(milliseconds: 100),
            curve: Curves.easeOutCubic,
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 140),
              curve: Curves.easeOutCubic,
              width: 30,
              height: 30,
              decoration: BoxDecoration(
                color: _hovered
                    ? widget.color.withValues(alpha: _pressed ? 0.20 : 0.12)
                    : Colors.transparent,
                borderRadius: BorderRadius.circular(7),
                border: Border.all(
                  color: _hovered
                      ? widget.color.withValues(alpha: 0.55)
                      : widget.color.withValues(alpha: 0.22),
                  width: _hovered ? 1.2 : 1.0,
                ),
                boxShadow: _hovered && !_pressed
                    ? [BoxShadow(
                        color: widget.color.withValues(alpha: 0.18),
                        blurRadius: 8,
                        spreadRadius: 0,
                      )]
                    : [],
              ),
              child: Center(
                child: Icon(widget.icon,
                    size: 14,
                    color: widget.color.withValues(
                        alpha: _hovered ? 1.0 : 0.75)),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Hover Button (reports-local) — scale + pressed + shadow bloom
// ──────────────────────────────────────────────────────────────────────────────

class _ReportHoverButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final Widget child;
  final Color color;
  final Color textColor;
  final EdgeInsetsGeometry padding;
  final bool outlined;

  const _ReportHoverButton({
    required this.onPressed,
    required this.child,
    required this.color,
    required this.textColor,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
    this.outlined = false,
  });

  @override
  State<_ReportHoverButton> createState() => _ReportHoverButtonState();
}

class _ReportHoverButtonState extends State<_ReportHoverButton> {
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

    // Two-layer glow: ambient bloom + subtle directional lift
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
                    ? widget.color.withValues(alpha: _hovered ? 0.8 : 0.55)
                    : Colors.transparent,
                width: 1.5,
              ),
              boxShadow: shadows,
            ),
            child: Center(
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
      ),
    );
  }
}



Future<bool> _showReportConfirmDialog({
  required BuildContext context,
  required ThemeProvider tp,
  required String title,
  required String message,
  String confirmLabel = 'Remove',
}) async {
  final danger = tp.getDangerColor();
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
              width: 58, height: 58,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: danger.withValues(alpha: 0.12),
                border: Border.all(color: danger.withValues(alpha: 0.3), width: 1.5),
              ),
              child: Icon(Icons.delete_forever_rounded, color: danger, size: 28),
            ),
            const SizedBox(height: 16),
            Text(title,
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold,
                    color: tp.getTextColor(), fontFamily: 'Courier Prime'),
                textAlign: TextAlign.center),
            const SizedBox(height: 10),
            Text(message,
                style: TextStyle(fontSize: 13, color: tp.getTextSecondaryColor(), height: 1.5),
                textAlign: TextAlign.center),
            const SizedBox(height: 24),
            Divider(color: tp.getBorderColor()),
            const SizedBox(height: 16),
            Row(children: [
              Expanded(
                child: _ReportHoverButton(
                  onPressed: () => Navigator.pop(context, false),
                  color: tp.getBorderColor(),
                  textColor: tp.getTextMutedColor(),
                  outlined: true,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  child: const Text('Cancel', style: TextStyle(fontWeight: FontWeight.w600)),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: _ReportHoverButton(
                  onPressed: () => Navigator.pop(context, true),
                  color: danger,
                  textColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  child: Text(confirmLabel, style: const TextStyle(fontWeight: FontWeight.w600)),
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

// ──────────────────────────────────────────────────────────────────────────────
// Data classes
// ──────────────────────────────────────────────────────────────────────────────

class _MitreTechnique {
  final String id, name, tactic, severity;
  final int count;
  final Color color;
  const _MitreTechnique(
      this.id, this.name, this.tactic, this.count, this.severity, this.color);
}

class _ReportHistoryEntry {
  final String filename, savedPath, format, period;
  final DateTime generatedAt;
  final int threatCount;
  const _ReportHistoryEntry(
      {required this.filename,
      required this.savedPath,
      required this.format,
      required this.period,
      required this.generatedAt,
      required this.threatCount});
}