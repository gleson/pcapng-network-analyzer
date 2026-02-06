"""
Report Generator Module
Generates PDF and HTML reports from PCAP analysis results
"""
import os
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

from jinja2 import Template


SEVERITY_COLORS = {
    'critical': colors.HexColor('#dc3545'),
    'high': colors.HexColor('#e67e22'),
    'medium': colors.HexColor('#f39c12'),
    'low': colors.HexColor('#95a5a6'),
}


def generate_pdf_report(results, output_path):
    """Generate PDF report from analysis results"""
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor('#2c3e50'),
        spaceAfter=20, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', parent=styles['Normal'],
        fontSize=10, textColor=colors.HexColor('#7f8c8d'),
        alignment=TA_CENTER, spaceAfter=20
    )

    # Title
    story.append(Paragraph("PCAP Network Analysis Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        subtitle_style
    ))

    # Summary
    summary = results.get('summary', {})
    story.append(Paragraph("Executive Summary", styles['Heading1']))

    summary_data = [
        ['Metric', 'Value'],
        ['Filename', summary.get('filename', 'N/A')],
        ['Analyzed At', str(summary.get('analyzed_at', 'N/A'))[:19]],
        ['Total Packets', f"{summary.get('packet_count', 0):,}"],
        ['Total Bytes', f"{summary.get('total_bytes', 0):,}"],
        ['Duration', f"{summary.get('duration', 0):.2f}s"],
        ['Unique IPs', str(len(results.get('ips', [])))],
        ['Protocols', str(len(results.get('protocols', [])))],
        ['Security Alerts', str(len(results.get('alerts', [])))],
    ]

    t = Table(summary_data, colWidths=[2.5*inch, 4*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Alerts
    alerts = results.get('alerts', [])
    story.append(Paragraph("Security Alerts", styles['Heading1']))

    if alerts:
        # Severity summary
        sev_counts = {}
        for a in alerts:
            s = a.get('severity', 'unknown')
            sev_counts[s] = sev_counts.get(s, 0) + 1

        sev_data = [['Severity', 'Count']]
        for s in ['critical', 'high', 'medium', 'low']:
            if s in sev_counts:
                sev_data.append([s.upper(), str(sev_counts[s])])

        st = Table(sev_data, colWidths=[2*inch, 1.5*inch])
        st.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(st)
        story.append(Spacer(1, 12))

        # Alert details (top 20)
        story.append(Paragraph("Alert Details", styles['Heading2']))
        alert_data = [['Severity', 'Title', 'Description', 'IP']]
        for a in alerts[:20]:
            alert_data.append([
                a.get('severity', '').upper(),
                a.get('title', ''),
                a.get('description', '')[:80],
                a.get('ip', '')
            ])

        at = Table(alert_data, colWidths=[0.8*inch, 1.8*inch, 3*inch, 1.2*inch])
        at.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(at)
    else:
        story.append(Paragraph("No security alerts detected.", styles['Normal']))

    story.append(PageBreak())

    # Protocols
    protocols = results.get('protocols', [])[:15]
    story.append(Paragraph("Protocol Statistics", styles['Heading1']))

    if protocols:
        proto_data = [['Protocol', 'Packets', 'Bytes', '%', 'Risk']]
        for p in protocols:
            proto_data.append([
                p.get('name', ''),
                f"{p.get('packets', 0):,}",
                f"{p.get('bytes', 0):,}",
                f"{p.get('percentage', 0):.1f}%",
                p.get('risk_level', '').upper()
            ])

        pt = Table(proto_data, colWidths=[1.3*inch, 1.3*inch, 1.5*inch, 0.8*inch, 0.8*inch])
        pt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ecc71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        story.append(pt)

    story.append(Spacer(1, 20))

    # Top IPs
    ips = results.get('ips', [])[:20]
    story.append(Paragraph("Top IP Addresses by Traffic", styles['Heading1']))

    if ips:
        ip_data = [['IP Address', 'Type', 'Sent', 'Received', 'Alerts']]
        for ip in ips:
            ip_type = 'Local' if ip.get('is_local', False) else 'External'
            ip_data.append([
                ip.get('ip', ''),
                ip_type,
                f"{ip.get('bytes_sent', 0):,}",
                f"{ip.get('bytes_received', 0):,}",
                str(ip.get('alert_count', 0))
            ])

        it = Table(ip_data, colWidths=[2*inch, 0.8*inch, 1.3*inch, 1.3*inch, 0.7*inch])
        it.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#9b59b6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        story.append(it)

    # Footer
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle(
        'Footer', parent=styles['Normal'],
        fontSize=8, textColor=colors.grey, alignment=TA_CENTER
    )
    story.append(Paragraph("Generated by PCAP Network Analyzer v3.0", footer_style))

    doc.build(story)


def generate_html_report(results):
    """Generate standalone HTML report"""
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Analysis Report - {{ summary.filename }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; color: #2c3e50; line-height: 1.6; }
        .container { max-width: 1100px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #2c3e50, #3498db); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header p { opacity: 0.8; font-size: 14px; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; overflow: hidden; }
        .card-header { padding: 15px 20px; font-weight: 600; font-size: 16px; border-bottom: 2px solid #f0f0f0; }
        .card-body { padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .metric { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); border-left: 4px solid #3498db; }
        .metric h3 { font-size: 12px; text-transform: uppercase; color: #7f8c8d; margin-bottom: 5px; }
        .metric .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
        .metric.danger { border-left-color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f8f9fa; text-align: left; padding: 10px 12px; font-weight: 600; text-transform: uppercase; font-size: 11px; color: #7f8c8d; border-bottom: 2px solid #dee2e6; }
        td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
        tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; color: white; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #e67e22; }
        .badge-medium { background: #f39c12; color: #333; }
        .badge-low { background: #95a5a6; }
        .badge-success { background: #2ecc71; }
        .badge-danger { background: #e74c3c; }
        .footer { text-align: center; padding: 20px; color: #95a5a6; font-size: 12px; }
        @media print { body { background: white; } .container { max-width: 100%; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PCAP Network Analysis Report</h1>
            <p>File: {{ summary.filename }} | Generated: {{ generated_at }}</p>
        </div>

        <div class="grid">
            <div class="metric">
                <h3>Total Packets</h3>
                <div class="value">{{ "{:,}".format(summary.packet_count|default(0)) }}</div>
            </div>
            <div class="metric">
                <h3>Total Bytes</h3>
                <div class="value">{{ "{:,}".format(summary.total_bytes|default(0)) }}</div>
            </div>
            <div class="metric">
                <h3>Duration</h3>
                <div class="value">{{ "%.1f"|format(summary.duration|default(0)) }}s</div>
            </div>
            <div class="metric">
                <h3>Unique IPs</h3>
                <div class="value">{{ ips|length }}</div>
            </div>
            <div class="metric">
                <h3>Protocols</h3>
                <div class="value">{{ protocols|length }}</div>
            </div>
            <div class="metric danger">
                <h3>Security Alerts</h3>
                <div class="value">{{ alerts|length }}</div>
            </div>
        </div>

        {% if alerts %}
        <div class="card">
            <div class="card-header">Security Alerts ({{ alerts|length }})</div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Title</th>
                            <th>Description</th>
                            <th>IP</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in alerts[:30] %}
                        <tr>
                            <td><span class="badge badge-{{ alert.severity }}">{{ alert.severity|upper }}</span></td>
                            <td>{{ alert.category }}</td>
                            <td><strong>{{ alert.title }}</strong></td>
                            <td>{{ alert.description }}</td>
                            <td><code>{{ alert.ip }}</code></td>
                            <td style="font-size:11px;">{{ alert.recommendation }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <div class="card">
            <div class="card-header">Protocol Statistics</div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>%</th><th>Risk</th></tr>
                    </thead>
                    <tbody>
                        {% for proto in protocols[:15] %}
                        <tr>
                            <td><strong>{{ proto.name }}</strong></td>
                            <td>{{ "{:,}".format(proto.packets) }}</td>
                            <td>{{ "{:,}".format(proto.bytes) }}</td>
                            <td>{{ "%.1f"|format(proto.percentage) }}%</td>
                            <td>
                                {% if proto.risk_level == 'high' %}<span class="badge badge-danger">HIGH</span>
                                {% elif proto.risk_level == 'medium' %}<span class="badge badge-medium">MEDIUM</span>
                                {% else %}<span class="badge badge-success">LOW</span>{% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header">Top IP Addresses</div>
            <div class="card-body">
                <table>
                    <thead>
                        <tr><th>IP</th><th>Type</th><th>Bytes Sent</th><th>Bytes Received</th><th>Protocols</th><th>Alerts</th></tr>
                    </thead>
                    <tbody>
                        {% for ip in ips[:25] %}
                        <tr>
                            <td><code>{{ ip.ip }}</code></td>
                            <td>{{ 'Local' if ip.is_local else 'External' }}</td>
                            <td>{{ "{:,}".format(ip.bytes_sent) }}</td>
                            <td>{{ "{:,}".format(ip.bytes_received) }}</td>
                            <td>{{ ip.protocols|join(', ') if ip.protocols else '-' }}</td>
                            <td>{% if ip.alert_count > 0 %}<span class="badge badge-danger">{{ ip.alert_count }}</span>{% else %}0{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            Generated by PCAP Network Analyzer v3.0 | {{ generated_at }}
        </div>
    </div>
</body>
</html>"""

    template = Template(html_template)

    return template.render(
        summary=results.get('summary', {}),
        ips=results.get('ips', []),
        protocols=results.get('protocols', []),
        alerts=results.get('alerts', []),
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
