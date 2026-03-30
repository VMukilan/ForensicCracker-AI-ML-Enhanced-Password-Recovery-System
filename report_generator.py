"""
report_generator.py
===================
Generates professional forensic PDF reports using reportlab.
Includes:
- Case metadata and chain-of-custody header
- Executive summary
- Per-hash analysis table
- Performance metrics and charts
- NIST/ACPO compliance notes
- Examiner signature block
"""

import os
import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """
    Generates a structured forensic PDF report.
    Falls back to plain text if reportlab is not installed.
    """

    def generate(self, case_id: str, examiner: str,
                 results: list, log_file: str = None) -> str:
        """
        Generate forensic report.
        Returns path to generated report file.
        """
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("forensic_reports")
        output_dir.mkdir(exist_ok=True)

        if REPORTLAB_AVAILABLE:
            path = output_dir / f"{case_id}_{ts}_report.pdf"
            self._generate_pdf(str(path), case_id, examiner, results, log_file)
        else:
            path = output_dir / f"{case_id}_{ts}_report.txt"
            self._generate_text(str(path), case_id, examiner, results, log_file)

        return str(path)

    def _generate_pdf(self, path: str, case_id: str, examiner: str,
                      results: list, log_file: str):
        doc = SimpleDocTemplate(
            path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=1 * inch,
            bottomMargin=1 * inch
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            'ForensicTitle',
            parent=styles['Title'],
            fontSize=18,
            spaceAfter=6,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1a1a2e')
        )
        heading_style = ParagraphStyle(
            'ForensicHeading',
            parent=styles['Heading2'],
            fontSize=13,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor('#16213e')
        )
        body_style = ParagraphStyle(
            'ForensicBody',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=4,
            leading=14
        )
        mono_style = ParagraphStyle(
            'Mono',
            parent=styles['Normal'],
            fontSize=9,
            fontName='Courier',
            spaceAfter=2
        )

        # ── Title Block ───────────────────────────────────────────────────────
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph("DIGITAL FORENSIC EXAMINATION REPORT", title_style))
        story.append(Paragraph("Password Recovery Analysis", styles['Heading3']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a1a2e')))
        story.append(Spacer(1, 0.15 * inch))

        # ── Case Metadata ─────────────────────────────────────────────────────
        now = datetime.datetime.utcnow()
        meta_data = [
            ['Case Identifier:', case_id],
            ['Examining Officer:', examiner],
            ['Report Date (UTC):', now.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Tool:', 'ForensicCracker v2.0 (AI/ML Enhanced)'],
            ['Classification:', 'RESTRICTED - LAW ENFORCEMENT USE ONLY'],
            ['Log File:', str(log_file) if log_file else 'N/A'],
        ]

        meta_table = Table(meta_data, colWidths=[2 * inch, 4.5 * inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f5f5f5'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.2 * inch))

        # ── Chain of Custody Notice ───────────────────────────────────────────
        story.append(Paragraph("CHAIN OF CUSTODY", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph(
            "All evidence processed in this report was handled in accordance with "
            "ACPO Good Practice Guide for Digital Evidence (v5) and NIST SP 800-101 "
            "Guidelines on Mobile Device Forensics. The forensic log file is "
            "HMAC-SHA256 signed with a session key. Any post-analysis modification "
            "of the log file will break the cryptographic chain and be detectable.",
            body_style
        ))
        story.append(Spacer(1, 0.15 * inch))

        # ── Executive Summary ─────────────────────────────────────────────────
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))

        total = len(results)
        cracked = [r for r in results if r.get('password')]
        failed = total - len(cracked)
        avg_time = sum(r.get('time', 0) for r in cracked) / max(len(cracked), 1)

        summary_text = (
            f"This examination analysed <b>{total}</b> cryptographic hash value(s) "
            f"recovered from digital evidence. Password recovery was successful for "
            f"<b>{len(cracked)}</b> of {total} hashes "
            f"({len(cracked)/max(total,1):.0%} success rate). "
            f"{failed} hash(es) were not recovered within the configured attack parameters. "
            f"The average recovery time for successful attempts was "
            f"<b>{avg_time:.3f} seconds</b>."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.15 * inch))

        # ── Results Table ─────────────────────────────────────────────────────
        story.append(Paragraph("DETAILED RESULTS", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))

        table_data = [['Username', 'Hash Type', 'Method', 'Attempts', 'Time (s)', 'Recovered', 'Password']]
        for r in results:
            password = r.get('password', '')
            display_pw = password if password else '[ Not Recovered ]'
            table_data.append([
                r.get('username', 'N/A'),
                r.get('hash_type', 'N/A'),
                (r.get('method', 'N/A') or '')[:22],
                f"{r.get('attempts', 0):,}",
                f"{r.get('time', 0):.3f}",
                'YES' if password else 'NO',
                display_pw
            ])

        col_widths = [0.9*inch, 0.9*inch, 1.5*inch, 0.8*inch, 0.7*inch, 0.6*inch, 1.1*inch]
        results_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#aaaaaa')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('ALIGN', (3, 0), (5, -1), 'CENTER'),
            # Highlight recovered rows
            *[('TEXTCOLOR', (6, i+1), (6, i+1), colors.HexColor('#c0392b'))
              for i, r in enumerate(results) if r.get('password')],
            *[('FONTNAME', (6, i+1), (6, i+1), 'Courier-Bold')
              for i, r in enumerate(results) if r.get('password')],
        ]))
        story.append(results_table)
        story.append(Spacer(1, 0.2 * inch))

        # ── Methodology ───────────────────────────────────────────────────────
        story.append(Paragraph("METHODOLOGY", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        methodology_text = """
        ForensicCracker v2.0 employs a multi-strategy password recovery approach:
        <br/><br/>
        <b>1. Dictionary Attack:</b> Multi-threaded streaming wordlist attack with 
        Bloom filter deduplication and encoding-variant testing (UTF-8, Latin-1, case variants).
        <br/><br/>
        <b>2. Brute Force Attack:</b> Systematic enumeration with configurable character sets 
        and checkpoint/resume capability for long-running attacks.
        <br/><br/>
        <b>3. Hybrid Attack:</b> Combines rule-based mutations (leetspeak, prefix/suffix, 
        case variants) with PCFG (Probabilistic Context-Free Grammar) and Markov chain 
        n-gram generation, ordered by statistical probability.
        <br/><br/>
        <b>4. AI Attack:</b> Semantic expansion, keyboard walk patterns, and Markov chain 
        sampling trained on the provided wordlist corpus.
        <br/><br/>
        <b>5. Ensemble Mode:</b> All four methods execute concurrently. The first method 
        to recover the password wins and all others are terminated.
        <br/><br/>
        <b>Attack Recommendation:</b> A rule-based decision tree combined with a UCB1 
        multi-armed bandit provides adaptive, explainable attack method recommendations 
        with confidence scores and session-persistent learning.
        """
        story.append(Paragraph(methodology_text, body_style))
        story.append(Spacer(1, 0.15 * inch))

        # ── Legal / Disclaimer ────────────────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("LEGAL NOTICE AND DISCLAIMER", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        legal_text = (
            "This report is produced solely for the purpose of a lawful forensic "
            "investigation. The tool ForensicCracker v2.0 is intended for use by "
            "authorised law enforcement personnel, licensed digital forensics examiners, "
            "and academic researchers with appropriate ethical approval. Unauthorised use "
            "of this tool or the information contained herein may constitute a criminal "
            "offence under the Computer Misuse Act 1990 (UK), 18 U.S.C. § 1030 (US), "
            "or equivalent legislation in other jurisdictions. The examining officer "
            "named in this report takes full responsibility for the lawful conduct of "
            "this examination."
        )
        story.append(Paragraph(legal_text, body_style))
        story.append(Spacer(1, 0.3 * inch))

        # ── Signature Block ───────────────────────────────────────────────────
        sig_data = [
            ['Examining Officer:', examiner],
            ['Signature:', '________________________________'],
            ['Date:', now.strftime("%d %B %Y")],
            ['Report Generated:', now.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ]
        sig_table = Table(sig_data, colWidths=[2 * inch, 3 * inch])
        sig_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(sig_table)

        doc.build(story)

    def _generate_text(self, path: str, case_id: str, examiner: str,
                       results: list, log_file: str):
        """Plain text fallback if reportlab not installed."""
        now = datetime.datetime.utcnow()
        lines = [
            "=" * 70,
            "  DIGITAL FORENSIC EXAMINATION REPORT",
            "  Password Recovery Analysis",
            "=" * 70,
            f"  Case ID   : {case_id}",
            f"  Examiner  : {examiner}",
            f"  Date (UTC): {now.isoformat()}",
            f"  Tool      : ForensicCracker v2.0",
            f"  Log File  : {log_file or 'N/A'}",
            "=" * 70,
            "",
            "RESULTS:",
            "-" * 70,
        ]
        for r in results:
            lines.append(f"  Hash Type : {r.get('hash_type', 'N/A')}")
            lines.append(f"  Method    : {r.get('method', 'N/A')}")
            lines.append(f"  Attempts  : {r.get('attempts', 0):,}")
            lines.append(f"  Time      : {r.get('time', 0):.3f}s")
            lines.append(f"  Password  : {r.get('password', '[ Not Recovered ]')}")
            lines.append("")

        with open(path, 'w') as f:
            f.write('\n'.join(lines))
