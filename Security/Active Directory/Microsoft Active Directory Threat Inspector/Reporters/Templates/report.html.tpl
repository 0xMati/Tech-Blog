<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TOOL_NAME}} - Report</title>
    <style>
        :root {
            --bg: #0d1117;
            --bg-card: #161b22;
            --bg-table: #21262d;
            --border: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
            --severity-critical: #ff2d55;
            --severity-high: #ff6b35;
            --severity-medium: #ffc107;
            --severity-low: #58a6ff;
            --severity-info: #6c757d;
            --grade-a: #3fb950;
            --grade-b: #56d364;
            --grade-c: #d29922;
            --grade-d: #ff6b35;
            --grade-e: #ff2d55;
            --green: #3fb950;
            --red: #f85149;
            --yellow: #d29922;
            --cyan: #39c5cf;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 3rem;
            max-width: 1500px;
            margin: 0 auto;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        /* ===== Header ===== */
        .header {
            text-align: center;
            padding: 2.5rem 0 2rem;
            border-bottom: 2px solid var(--accent-blue);
            margin-bottom: 2rem;
        }
        .header h1 {
            font-size: 2.2rem;
            color: var(--accent-blue);
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        .subtitle {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* ===== Navigation ===== */
        .section-nav {
            position: sticky;
            top: 0;
            background: var(--bg);
            padding: 0.8rem 0;
            z-index: 100;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
            display: flex;
            gap: 0.4rem;
            flex-wrap: wrap;
        }
        .section-nav a {
            color: var(--accent-blue);
            text-decoration: none;
            font-size: 0.82rem;
            padding: 0.3rem 0.8rem;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: var(--bg-card);
            transition: background 0.2s, border-color 0.2s;
        }
        .section-nav a:hover {
            background: var(--bg-table);
            border-color: var(--accent-blue);
        }

        /* ===== Section Headers ===== */
        .section-header {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            color: var(--accent-blue);
            font-size: 1.4rem;
            margin: 2.5rem 0 0.5rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        .section-icon { font-size: 1.3rem; }
        .section-intro {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin: -0.2rem 0 1.5rem 0;
        }

        /* ===== Score Dashboard ===== */
        .score-dashboard {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
            align-items: start;
        }
        .score-hero {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 2rem 2.5rem;
            text-align: center;
            min-width: 220px;
            position: relative;
            overflow: hidden;
        }
        .score-hero::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 4px;
            border-radius: 14px 14px 0 0;
        }
        .score-hero.grade-a::before { background: var(--grade-a); }
        .score-hero.grade-b::before { background: var(--grade-b); }
        .score-hero.grade-c::before { background: var(--grade-c); }
        .score-hero.grade-d::before { background: var(--grade-d); }
        .score-hero.grade-e::before { background: var(--grade-e); }

        .score-ring {
            width: 140px; height: 140px;
            border-radius: 50%;
            margin: 0 auto 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        .score-ring::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: 50%;
            border: 6px solid var(--border);
        }
        .score-ring .score-number {
            font-size: 3rem;
            font-weight: 800;
            line-height: 1;
        }
        .score-grade {
            font-size: 1.4rem;
            font-weight: 700;
            margin-top: 0.3rem;
        }
        .score-label {
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 0.2rem;
        }

        .grade-a .score-number, .grade-a .score-grade { color: var(--grade-a); }
        .grade-b .score-number, .grade-b .score-grade { color: var(--grade-b); }
        .grade-c .score-number, .grade-c .score-grade { color: var(--grade-c); }
        .grade-d .score-number, .grade-d .score-grade { color: var(--grade-d); }
        .grade-e .score-number, .grade-e .score-grade { color: var(--grade-e); }

        .score-metrics {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.2rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .metric-card::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            border-radius: 10px 10px 0 0;
        }
        .metric-card.mc-critical::after { background: var(--severity-critical); }
        .metric-card.mc-high::after { background: var(--severity-high); }
        .metric-card.mc-medium::after { background: var(--severity-medium); }
        .metric-card.mc-low::after { background: var(--severity-low); }

        .metric-card .mc-icon { font-size: 1.3rem; margin-bottom: 0.3rem; }
        .metric-card .mc-value {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1.2;
        }
        .metric-card .mc-label {
            color: var(--text-secondary);
            font-size: 0.78rem;
            margin-top: 0.2rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* ===== Environment Summary ===== */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .summary-metric {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.2rem 1rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        .summary-metric::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 10px 10px 0 0; }
        .summary-metric .metric-icon { font-size: 1.5rem; margin-bottom: 0.2rem; }
        .summary-metric .metric-value { font-size: 2.2rem; font-weight: 700; line-height: 1.1; }
        .summary-metric .metric-label { color: var(--text-secondary); font-size: 0.78rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.5px; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; }
        .summary-category { margin-bottom: 1.5rem; }
        .summary-category h3 { color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 0; margin-bottom: 0.8rem; border: none; }
        .summary-row { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }
        .summary-row:last-child { border-bottom: none; }
        .row-label { display: flex; align-items: center; gap: 0.6rem; color: var(--text-primary); font-size: 0.88rem; }
        .row-label .icon { font-size: 1rem; width: 1.5rem; text-align: center; }
        .row-value { font-weight: 600; font-size: 0.88rem; display: flex; align-items: center; gap: 0.5rem; }
        .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .dot.green { background: var(--green); box-shadow: 0 0 6px var(--green); }
        .dot.yellow { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
        .dot.red { background: var(--red); box-shadow: 0 0 6px var(--red); }

        /* Severity bar */
        .severity-bar {
            display: flex;
            height: 32px;
            border-radius: 8px;
            overflow: hidden;
            margin: 1rem 0 1.5rem 0;
            background: var(--bg-table);
        }
        .severity-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.8rem;
            color: #fff;
            min-width: 40px;
            transition: width 0.3s;
        }
        .severity-legend {
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }
        .severity-legend-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        .severity-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }
        .severity-dot.critical { background: var(--severity-critical); }
        .severity-dot.high { background: var(--severity-high); }
        .severity-dot.medium { background: var(--severity-medium); }
        .severity-dot.low { background: var(--severity-low); }
        .severity-dot.info { background: var(--severity-info); }

        /* ===== DC Section ===== */
        .dc-section { margin: 2rem 0; }

        .dc-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 10px;
            overflow: hidden;
            font-size: 0.85rem;
        }
        .dc-table thead th {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 0.75rem 0.8rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--accent-blue);
            position: sticky;
            top: 0;
        }
        .dc-table tbody td {
            padding: 0.6rem 0.8rem;
            border-bottom: 1px solid var(--border);
        }
        .dc-table tbody tr:hover { background: rgba(88,166,255,0.05); }

        .dc-status {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .dc-status.ok { background: #0d2818; color: var(--green); }
        .dc-status.warning { background: #2d2000; color: var(--yellow); }
        .dc-status.unreachable { background: #2d0000; color: var(--red); }

        .badge {
            background: var(--bg-table);
            color: var(--text-secondary);
            padding: 0.15rem 0.6rem;
            border-radius: 10px;
            font-size: 0.8rem;
            font-weight: normal;
        }

        /* ===== Category / Findings Section ===== */
        .category-section {
            margin: 1.5rem 0;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--border);
            background: var(--bg-card);
        }

        .category-header {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 1rem 1.2rem;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            transition: background 0.2s;
        }
        .category-header:hover { background: #262c36; }
        .category-header::-webkit-details-marker { display: none; }
        .category-header::marker { display: none; content: ''; }
        .category-header::before {
            content: '\25BC';
            font-size: 0.65rem;
            transition: transform 0.2s;
            display: inline-block;
            color: var(--accent-blue);
        }
        .category-section:not([open]) .category-header::before {
            transform: rotate(-90deg);
        }

        .finding-section {
            margin: 0.5rem 1rem;
            border-left: 3px solid var(--border);
            border-radius: 0 8px 8px 0;
            background: rgba(13,17,23,0.5);
        }
        .finding-section[open] { border-left-color: var(--accent-blue); }

        .finding-header {
            padding: 0.8rem 1rem;
            font-weight: 500;
            cursor: pointer;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.9rem;
            color: var(--text-primary);
            transition: background 0.15s;
        }
        .finding-header:hover { background: rgba(88,166,255,0.05); }
        .finding-header::-webkit-details-marker { display: none; }
        .finding-header::marker { display: none; content: ''; }
        .finding-header::before {
            content: '\25BC';
            font-size: 0.55rem;
            transition: transform 0.2s;
            display: inline-block;
        }
        .finding-section:not([open]) .finding-header::before {
            transform: rotate(-90deg);
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin: 0 0 0.5rem 0;
            font-size: 0.82rem;
        }
        .findings-table thead th {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 0.65rem 0.7rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--accent-blue);
            white-space: nowrap;
        }
        .findings-table tbody td {
            padding: 0.55rem 0.7rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        .findings-table tbody tr:hover { background: rgba(88,166,255,0.05); }

        .object-dn {
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 0.72rem;
            word-break: break-all;
            max-width: 250px;
            color: var(--text-secondary);
        }

        .severity-badge {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 5px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .severity-badge.critical { background: rgba(255,45,85,0.15); color: var(--severity-critical); border: 1px solid var(--severity-critical); }
        .severity-badge.high { background: rgba(255,107,53,0.15); color: var(--severity-high); border: 1px solid var(--severity-high); }
        .severity-badge.medium { background: rgba(255,193,7,0.15); color: var(--severity-medium); border: 1px solid var(--severity-medium); }
        .severity-badge.low { background: rgba(88,166,255,0.15); color: var(--severity-low); border: 1px solid var(--severity-low); }
        .severity-badge.informational { background: rgba(108,117,125,0.15); color: var(--severity-info); border: 1px solid var(--severity-info); }

        .severity-critical td:first-child { border-left: 3px solid var(--severity-critical); }
        .severity-high td:first-child { border-left: 3px solid var(--severity-high); }
        .severity-medium td:first-child { border-left: 3px solid var(--severity-medium); }
        .severity-low td:first-child { border-left: 3px solid var(--severity-low); }

        /* ===== Section Toolbar ===== */
        .section-toolbar {
            display: flex;
            gap: 0.5rem;
            margin: 1rem 0;
        }
        .section-toolbar button {
            background: var(--bg-card);
            color: var(--accent-blue);
            border: 1px solid var(--accent-blue);
            border-radius: 6px;
            padding: 0.4rem 1rem;
            cursor: pointer;
            font-size: 0.8rem;
            font-weight: 600;
            transition: background 0.2s, color 0.2s;
        }
        .section-toolbar button:hover {
            background: var(--accent-blue);
            color: var(--bg);
        }

        /* ===== Protocol Audit — Donut Charts ===== */
        .protocol-audit { margin: 2rem 0; }
        .protocol-audit h3 {
            color: var(--accent-blue);
            font-size: 1.1rem;
            margin: 1.5rem 0 0.5rem 0;
        }

        .chart-row {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            justify-content: center;
            margin: 1.5rem 0;
        }
        .chart-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem 2rem;
            border: 1px solid var(--border);
            text-align: center;
            min-width: 260px;
        }
        .chart-card .chart-title {
            color: var(--text-secondary);
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 1rem;
        }
        .donut-wrapper {
            position: relative;
            width: 160px; height: 160px;
            margin: 0 auto 1rem auto;
        }
        .donut-wrapper svg { transform: rotate(-90deg); }
        .donut-center {
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        .donut-center .big { font-size: 1.6rem; font-weight: 800; display: block; }
        .donut-center .small { font-size: 0.7rem; color: var(--text-secondary); }
        .chart-legend {
            display: flex;
            justify-content: center;
            gap: 1.2rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
            font-size: 0.8rem;
        }
        .legend-item { display: flex; align-items: center; gap: 0.35rem; }
        .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

        .top-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.8rem;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }
        .top-table thead th {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 0.5rem 0.75rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--accent-blue);
        }
        .top-table tbody td {
            padding: 0.4rem 0.75rem;
            border-bottom: 1px solid var(--border);
        }
        .top-table tbody tr:hover { background: rgba(88,166,255,0.05); }

        .top-tables-row {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            margin: 1rem 0;
        }
        .top-tables-row > div { flex: 1; min-width: 280px; }

        /* Protocol — sub-headings, alert boxes, breakdown details */
        .proto-sub {
            color: var(--text-secondary);
            font-size: 0.92rem;
            font-weight: 600;
            margin: 1.4rem 0 0.5rem 0;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem;
        }
        .proto-detail-table { max-width: 700px; }
        .proto-wide-table { max-width: 100%; }
        .proto-detail-table td:nth-child(3),
        .proto-detail-table td:nth-child(4),
        .proto-detail-table th:nth-child(3),
        .proto-detail-table th:nth-child(4) { text-align: right; }

        .rc4-type-summary { display: flex; gap: 1rem; margin: 0.5rem 0 1rem 0; }
        .rc4-type-badge {
            padding: 0.3rem 1rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.85rem;
        }
        .rc4-type-badge.tgt { background: rgba(255,45,85,0.15); color: #ff2d55; border: 1px solid rgba(255,45,85,0.3); }
        .rc4-type-badge.tgs { background: rgba(255,107,53,0.15); color: #ff6b35; border: 1px solid rgba(255,107,53,0.3); }

        .proto-alert {
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            padding: 0.8rem 1.2rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-size: 0.85rem;
            line-height: 1.5;
        }
        .proto-alert code { background: rgba(255,255,255,0.08); padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.82rem; }
        .alert-icon { font-size: 1.3rem; flex-shrink: 0; margin-top: 0.1rem; }
        .alert-critical {
            background: rgba(255,45,85,0.08);
            border: 1px solid rgba(255,45,85,0.3);
            color: #ff6b8a;
        }
        .alert-ok {
            background: rgba(0,230,118,0.08);
            border: 1px solid rgba(0,230,118,0.3);
            color: #00e676;
        }

        .aes-yes { color: #00e676; font-weight: 600; }
        .aes-no  { color: #ff2d55; font-weight: 600; }

        /* ===== Score Breakdown ===== */
        .score-breakdown { margin: 2rem 0; }
        .score-breakdown h2 { margin-bottom: 1rem; }

        .refs-cell { font-size: 0.72rem; max-width: 220px; word-break: break-all; }
        .refs-cell a { color: var(--accent-blue); text-decoration: none; }
        .refs-cell a:hover { text-decoration: underline; }

        /* ===== Footer ===== */
        .footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        .footer a { color: var(--accent-blue); text-decoration: none; }
        .footer a:hover { text-decoration: underline; }

        /* ===== Print ===== */
        @media print {
            body { background: white; color: #333; padding: 1rem; }
            .section-nav { display: none; }
            .score-hero, .metric-card, .chart-card { background: #f5f5f5; border: 1px solid #ddd; }
            .dc-table thead th, .findings-table thead th, .top-table thead th { background: #e0e0e0; color: #333; }
            .dc-table tbody td, .findings-table tbody td { border-color: #ddd; }
            .section-toolbar { display: none; }
            details, details[open] { display: block !important; }
            details > summary { list-style: none; }
            details > summary::-webkit-details-marker { display: none; }
            details > *:not(summary) { display: block !important; }
            .refs-cell a { color: #333; }
        }

        @media (max-width: 768px) {
            body { padding: 1rem; }
            .score-dashboard { grid-template-columns: 1fr; }
            .score-metrics { grid-template-columns: 1fr; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .grid-3 { grid-template-columns: 1fr; }
            .metric-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>

    <div class="header">
        <h1>&#x1F6E1; {{TOOL_NAME}}</h1>
        <div class="subtitle">{{COMPANY_NAME}} &mdash; v{{VERSION}} &mdash; {{DATE}}</div>
    </div>

    <!-- Navigation -->
    <nav class="section-nav">
        <a href="#score">Score</a>
        <a href="#env-summary">Environment</a>
        <a href="#forest">Forest</a>
        <a href="#dc">Domain Controllers</a>
        <a href="#protocol">Protocol Audit</a>
        <a href="#breakdown">Score Breakdown</a>
        <a href="#findings">Findings</a>
    </nav>

    <!-- Score Dashboard -->
    <div id="score" class="score-dashboard">
        <div class="score-hero {{GRADE_CLASS}}">
            <div class="score-ring">
                <span class="score-number">{{SCORE}}</span>
            </div>
            <div class="score-grade">Grade {{GRADE}}</div>
            <div class="score-label">out of 100</div>
        </div>
        <div>
            <div class="score-metrics">
                <div class="metric-card mc-critical">
                    <div class="mc-icon">&#x1F534;</div>
                    <div class="mc-value" style="color:var(--severity-critical)">{{CRITICAL_COUNT}}</div>
                    <div class="mc-label">Critical</div>
                </div>
                <div class="metric-card mc-high">
                    <div class="mc-icon">&#x1F7E0;</div>
                    <div class="mc-value" style="color:var(--severity-high)">{{HIGH_COUNT}}</div>
                    <div class="mc-label">High</div>
                </div>
                <div class="metric-card mc-medium">
                    <div class="mc-icon">&#x1F7E1;</div>
                    <div class="mc-value" style="color:var(--severity-medium)">{{MEDIUM_COUNT}}</div>
                    <div class="mc-label">Medium</div>
                </div>
                <div class="metric-card mc-low">
                    <div class="mc-icon">&#x1F535;</div>
                    <div class="mc-value" style="color:var(--severity-low)">{{LOW_COUNT}}</div>
                    <div class="mc-label">Low</div>
                </div>
            </div>
            <div class="severity-bar">
                {{SEVERITY_BAR}}
            </div>
            <div class="severity-legend">
                <span class="severity-legend-item"><span class="severity-dot critical"></span> Critical: <strong>{{CRITICAL_COUNT}}</strong></span>
                <span class="severity-legend-item"><span class="severity-dot high"></span> High: <strong>{{HIGH_COUNT}}</strong></span>
                <span class="severity-legend-item"><span class="severity-dot medium"></span> Medium: <strong>{{MEDIUM_COUNT}}</strong></span>
                <span class="severity-legend-item"><span class="severity-dot low"></span> Low: <strong>{{LOW_COUNT}}</strong></span>
                <span class="severity-legend-item"><span class="severity-dot info"></span> Info: <strong>{{INFO_COUNT}}</strong></span>
                <span style="margin-left:auto;color:var(--text-secondary)">Total: <strong>{{TOTAL_FINDINGS}}</strong> &mdash; Rules: <strong>{{RULES_EVALUATED}}</strong></span>
            </div>
        </div>
    </div>

    {{ENVIRONMENT_SUMMARY}}

    {{FOREST_DOMAINS}}

    {{DC_INVENTORY}}

    {{DC_CONNECTIVITY}}

    {{PROTOCOL_AUDIT}}

    {{SCORE_BREAKDOWN}}

    <!-- Findings -->
    <h2 id="findings" class="section-header"><span class="section-icon">&#x1F50D;</span> Detailed Findings</h2>
    <p class="section-intro">All findings grouped by category and rule. Click on a category or finding to expand details.</p>

    <div class="section-toolbar">
        <button onclick="document.querySelectorAll('.category-section').forEach(d=>d.open=true);document.querySelectorAll('.finding-section').forEach(d=>d.open=true)">&#9660; Expand All</button>
        <button onclick="document.querySelectorAll('.category-section').forEach(d=>d.open=false);document.querySelectorAll('.finding-section').forEach(d=>d.open=false)">&#9654; Collapse All</button>
    </div>

    {{CATEGORY_BLOCKS}}

    <div class="footer">
        <p>Generated by <strong>{{TOOL_NAME}}</strong> v{{VERSION}} on {{DATE}}</p>
        <p><strong>MATI</strong> &mdash; open-source Active Directory security assessment. <a href="https://github.com/0xMati/Tech-Blog/tree/main/Security/Active%20Directory/Microsoft%20Active%20Directory%20Threat%20Inspector" target="_blank">GitHub</a></p>
    </div>

    <script>
    window.addEventListener('beforeprint', function() {
        document.querySelectorAll('details').forEach(function(d) { d.setAttribute('open', ''); });
    });
    </script>

</body>
</html>
