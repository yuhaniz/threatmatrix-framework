// tm_dropdown.dart
// ─────────────────────────────────────────────────────────────────────────────
// Unified ThreatMatrix dropdown widget.
//
// KEY BEHAVIOURS
//   • Always opens BELOW the trigger — uses Overlay + CompositedTransformFollower
//     with targetAnchor: Alignment.bottomLeft / followerAnchor: Alignment.topLeft,
//     so screen position never flips the menu upward.
//   • Standardised item style across the whole app:
//       – Hollow radio-dot  (border only, no fill) when unselected
//       – Solid green dot   (filled + border)      when selected
//       – Selected row gets a green-tinted background + bold green label
//       – Unselected row gets a subtle hover tint  + normal weight secondary text
//   • Animated: arrow rotates 180° on open; menu fades + slides down into view.
//   • Dismiss: tap anywhere outside the menu.
//
// USAGE (both pages)
//   TmModernDropdown<String>(
//     value: _selectedPeriod,
//     items: _periods,
//     onChanged: (v) { if (v != null) setState(() => _selectedPeriod = v); },
//     tp: tp,
//   )
//   // Pass width: 200 if you need a fixed-width trigger (settings page style).
//   // Omit width (or pass null) to fill available space   (reports page style).
// ─────────────────────────────────────────────────────────────────────────────

import 'package:flutter/material.dart';
import 'threatmatrix_flutter_theme_provider.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Public widget
// ══════════════════════════════════════════════════════════════════════════════

class TmModernDropdown<T> extends StatefulWidget {
  final T value;
  final List<T> items;
  final ValueChanged<T?> onChanged;
  final ThemeProvider tp;

  /// Fixed pixel width for the trigger button.
  /// Pass [null] (default) to let it fill its parent (use inside Expanded).
  final double? width;

  const TmModernDropdown({
    super.key,
    required this.value,
    required this.items,
    required this.onChanged,
    required this.tp,
    this.width,
  });

  @override
  State<TmModernDropdown<T>> createState() => _TmModernDropdownState<T>();
}

class _TmModernDropdownState<T> extends State<TmModernDropdown<T>> {
  bool _hovered = false;
  bool _open    = false;

  OverlayEntry? _overlayEntry;
  final LayerLink _layerLink = LayerLink();

  // Key on the trigger Container so we can read its rendered width for the menu.
  final GlobalKey _triggerKey = GlobalKey();

  // ── open / close ────────────────────────────────────────────────────────────

  void _openMenu() {
    if (_open) { _closeMenu(); return; }

    // Measure the trigger's rendered size and its global position.
    final RenderBox box =
        _triggerKey.currentContext!.findRenderObject()! as RenderBox;
    final double triggerWidth  = box.size.width;
    final double triggerHeight = box.size.height;

    // Global Y of the trigger's bottom edge.
    final Offset globalOffset  = box.localToGlobal(Offset.zero);
    final double triggerBottom = globalOffset.dy + triggerHeight;

    // Available space below the trigger: screen height minus the trigger's
    // bottom edge, the 6 px gap, and a 16 px safety margin so the menu never
    // touches the very bottom of the screen.
    final double screenHeight   = MediaQuery.of(context).size.height;
    final double availableBelow = screenHeight - triggerBottom - 6 - 16;

    // Clamp: never taller than 280 px, never shorter than 80 px so at least
    // a few items are always visible.
    final double maxMenuHeight  = availableBelow.clamp(80.0, 280.0);

    _overlayEntry = OverlayEntry(
      builder: (_) => _TmDropdownOverlay<T>(
        layerLink:     _layerLink,
        triggerWidth:  triggerWidth,
        maxMenuHeight: maxMenuHeight,
        items:         widget.items,
        value:         widget.value,
        tp:            widget.tp,
        onSelected:    (v) { _closeMenu(); widget.onChanged(v); },
        onDismiss:     _closeMenu,
      ),
    );

    Overlay.of(context).insert(_overlayEntry!);
    setState(() => _open = true);
  }

  void _closeMenu() {
    _overlayEntry?.remove();
    _overlayEntry = null;
    if (mounted) setState(() => _open = false);
  }

  @override
  void dispose() {
    _closeMenu();
    super.dispose();
  }

  // ── build ────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final tp = widget.tp;

    return CompositedTransformTarget(
      link: _layerLink,
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => _hovered = true),
        onExit:  (_) => setState(() => _hovered = false),
        child: GestureDetector(
          onTap: _openMenu,
          child: AnimatedContainer(
            key:      _triggerKey,
            duration: const Duration(milliseconds: 150),
            width:    widget.width, // null → fill parent
            padding:  const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
            decoration: BoxDecoration(
              color: tp.isDarkMode
                  ? (_hovered || _open
                      ? const Color(0xFF1F2535)
                      : const Color(0xFF111318))
                  : (_hovered || _open
                      ? const Color(0xFFEEEEEE)
                      : const Color(0xFFF5F5F5)),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                color: _open
                    ? tp.getSuccessColor().withValues(alpha: 0.75)
                    : _hovered
                        ? tp.getSuccessColor().withValues(alpha: 0.55)
                        : tp.getBorderColor(),
                width: (_hovered || _open) ? 1.5 : 1.0,
              ),
              boxShadow: (_hovered || _open)
                  ? [
                      BoxShadow(
                        color:      tp.getSuccessColor().withValues(alpha: 0.10),
                        blurRadius: 8,
                        offset:     const Offset(0, 2),
                      )
                    ]
                  : [],
            ),
            child: Row(children: [
              // ── selected-value dot (always solid green when trigger is shown) ──
              Container(
                width:  7,
                height: 7,
                margin: const EdgeInsets.only(right: 8),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color:  tp.getSuccessColor(),
                  border: Border.all(
                    color: tp.getSuccessColor(),
                    width: 1.5,
                  ),
                ),
              ),
              // ── current value label ───────────────────────────────────────────
              Expanded(
                child: Text(
                  widget.value.toString(),
                  style: TextStyle(
                    fontSize:   13,
                    fontWeight: FontWeight.w500,
                    color:      tp.getTextColor(),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              // ── chevron (rotates when open) ───────────────────────────────────
              AnimatedRotation(
                turns:    _open ? 0.5 : 0.0,
                duration: const Duration(milliseconds: 180),
                child: Icon(
                  Icons.keyboard_arrow_down_rounded,
                  color: tp.getSuccessColor(),
                  size:  20,
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Overlay menu — always positioned BELOW the trigger
// ══════════════════════════════════════════════════════════════════════════════

class _TmDropdownOverlay<T> extends StatefulWidget {
  final LayerLink    layerLink;
  final double       triggerWidth;
  final double       maxMenuHeight; // clamped to available space below trigger
  final List<T>      items;
  final T            value;
  final ThemeProvider tp;
  final ValueChanged<T?> onSelected;
  final VoidCallback     onDismiss;

  const _TmDropdownOverlay({
    required this.layerLink,
    required this.triggerWidth,
    required this.maxMenuHeight,
    required this.items,
    required this.value,
    required this.tp,
    required this.onSelected,
    required this.onDismiss,
  });

  @override
  State<_TmDropdownOverlay<T>> createState() => _TmDropdownOverlayState<T>();
}

class _TmDropdownOverlayState<T> extends State<_TmDropdownOverlay<T>>
    with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double>   _fade;
  late Animation<Offset>   _slide;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync:    this,
      duration: const Duration(milliseconds: 180),
    );
    _fade  = CurvedAnimation(parent: _ctrl, curve: Curves.easeOut);
    _slide = Tween<Offset>(
      begin: const Offset(0, -0.03),
      end:   Offset.zero,
    ).animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOutCubic));
    _ctrl.forward();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final tp = widget.tp;
    return Stack(
      children: [
        // ── tap-outside barrier ───────────────────────────────────────────────
        Positioned.fill(
          child: GestureDetector(
            onTap:     widget.onDismiss,
            behavior:  HitTestBehavior.translucent,
            child:     const SizedBox.expand(),
          ),
        ),

        // ── menu, always below the trigger ────────────────────────────────────
        CompositedTransformFollower(
          link:              widget.layerLink,
          showWhenUnlinked:  false,
          targetAnchor:      Alignment.bottomLeft, // attach at bottom-left of trigger
          followerAnchor:    Alignment.topLeft,    // top-left of menu aligns there
          offset:            const Offset(0, 6),   // 6 px breathing gap
          child: SlideTransition(
            position: _slide,
            child: FadeTransition(
              opacity: _fade,
              child: Material(
                color:        Colors.transparent,
                child: Container(
                  width: widget.triggerWidth,
                  constraints: BoxConstraints(maxHeight: widget.maxMenuHeight),
                  decoration: BoxDecoration(
                    color:         tp.getCardColor(),
                    borderRadius:  BorderRadius.circular(10),
                    border:        Border.all(color: tp.getBorderColor()),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(
                            alpha: tp.isDarkMode ? 0.45 : 0.13),
                        blurRadius: 20,
                        offset:     const Offset(0, 6),
                      ),
                    ],
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(10),
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.symmetric(vertical: 6),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: widget.items.map((item) {
                          return _TmDropdownItem<T>(
                            item:       item,
                            isSelected: item == widget.value,
                            tp:         tp,
                            onTap:      () => widget.onSelected(item),
                          );
                        }).toList(),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Single item row — standardised style
// ══════════════════════════════════════════════════════════════════════════════

class _TmDropdownItem<T> extends StatefulWidget {
  final T            item;
  final bool         isSelected;
  final ThemeProvider tp;
  final VoidCallback  onTap;

  const _TmDropdownItem({
    required this.item,
    required this.isSelected,
    required this.tp,
    required this.onTap,
  });

  @override
  State<_TmDropdownItem<T>> createState() => _TmDropdownItemState<T>();
}

class _TmDropdownItemState<T> extends State<_TmDropdownItem<T>> {
  bool _hovered = false;

  @override
  Widget build(BuildContext context) {
    final tp         = widget.tp;
    final isSelected = widget.isSelected;

    return MouseRegion(
      cursor:  SystemMouseCursors.click,
      onEnter: (_) => setState(() => _hovered = true),
      onExit:  (_) => setState(() => _hovered = false),
      child: GestureDetector(
        onTap: widget.onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 100),
          margin:  const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
          decoration: BoxDecoration(
            color: isSelected
                ? tp.getSuccessColor().withValues(alpha: 0.10)
                : _hovered
                    ? (tp.isDarkMode
                        ? Colors.white.withValues(alpha: 0.05)
                        : Colors.black.withValues(alpha: 0.04))
                    : Colors.transparent,
            borderRadius: BorderRadius.circular(7),
          ),
          child: Row(children: [
            // ── radio-style dot ───────────────────────────────────────────────
            // Selected  → solid green fill + green border
            // Unselected → transparent fill + muted border (hollow ring)
            Container(
              width:  7,
              height: 7,
              margin: const EdgeInsets.only(right: 10),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: isSelected ? tp.getSuccessColor() : Colors.transparent,
                border: Border.all(
                  color: isSelected
                      ? tp.getSuccessColor()
                      : tp.getTextMutedColor().withValues(alpha: 0.45),
                  width: 1.5,
                ),
              ),
            ),
            // ── label ─────────────────────────────────────────────────────────
            Text(
              widget.item.toString(),
              style: TextStyle(
                fontSize:   13,
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.w400,
                color:      isSelected
                    ? tp.getSuccessColor()
                    : tp.getTextSecondaryColor(),
              ),
            ),
          ]),
        ),
      ),
    );
  }
}