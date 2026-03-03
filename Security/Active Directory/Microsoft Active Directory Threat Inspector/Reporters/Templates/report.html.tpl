<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TOOL_NAME}} - Report</title>
    <style>
        :root {
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --bg-table: #0f3460;
            --text-primary: #e6e6e6;
            --text-secondary: #a0a0b0;
            --accent-blue: #4cc9f0;
            --accent-purple: #7b2cbf;
            --severity-critical: #ff2d55;
            --severity-high: #ff6b35;
            --severity-medium: #ffc107;
            --severity-low: #4cc9f0;
            --severity-info: #6c757d;
            --grade-a: #00e676;
            --grade-b: #76ff03;
            --grade-c: #ffc107;
            --grade-d: #ff6b35;
            --grade-e: #ff2d55;
            --border: #2a2a4a;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        .header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid var(--accent-blue);
            margin-bottom: 2rem;
        }

        .header h1 {
            font-size: 2rem;
            color: var(--accent-blue);
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .score-section {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin: 2rem 0;
            flex-wrap: wrap;
        }

        .score-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            min-width: 180px;
            border: 1px solid var(--border);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .score-value {
            font-size: 3rem;
            font-weight: 800;
        }

        .grade-a .score-value { color: var(--grade-a); }
        .grade-b .score-value { color: var(--grade-b); }
        .grade-c .score-value { color: var(--grade-c); }
        .grade-d .score-value { color: var(--grade-d); }
        .grade-e .score-value { color: var(--grade-e); }

        .score-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 0.5rem;
        }

        .severity-summary {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 1.5rem 0;
            flex-wrap: wrap;
        }

        .severity-pill {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--bg-card);
            border-radius: 20px;
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            font-size: 0.9rem;
        }

        .severity-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .severity-dot.critical { background: var(--severity-critical); }
        .severity-dot.high     { background: var(--severity-high); }
        .severity-dot.medium   { background: var(--severity-medium); }
        .severity-dot.low      { background: var(--severity-low); }
        .severity-dot.info     { background: var(--severity-info); }

        /* DC Connectivity table */
        .dc-section {
            margin: 2rem 0;
        }

        .dc-section h2 {
            color: var(--accent-blue);
            font-size: 1.3rem;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }

        .dc-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }

        .dc-table thead th {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--accent-blue);
            white-space: nowrap;
        }

        .dc-table tbody td {
            padding: 0.65rem 0.75rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }

        .dc-table tbody tr:hover {
            background: rgba(76, 201, 240, 0.05);
        }

        .dc-status {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .dc-status.ok {
            background: rgba(0, 230, 118, 0.2);
            color: var(--grade-a);
            border: 1px solid var(--grade-a);
        }

        .dc-status.warning {
            background: rgba(255, 193, 7, 0.2);
            color: var(--severity-medium);
            border: 1px solid var(--severity-medium);
        }

        .dc-status.unreachable {
            background: rgba(255, 45, 85, 0.2);
            color: var(--severity-critical);
            border: 1px solid var(--severity-critical);
        }

        .category-header {
            color: var(--accent-blue);
            font-size: 1.3rem;
            margin-top: 0;
            margin-bottom: 0.5rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            list-style: none;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            user-select: none;
        }

        .category-header::-webkit-details-marker { display: none; }
        .category-header::marker { display: none; content: ''; }

        .category-header::before {
            content: '\25BC';
            font-size: 0.75rem;
            transition: transform 0.2s;
            display: inline-block;
        }

        .category-section:not([open]) .category-header::before {
            transform: rotate(-90deg);
        }

        .category-section {
            margin-top: 2rem;
            margin-bottom: 0.5rem;
        }

        .badge {
            background: var(--bg-table);
            color: var(--text-secondary);
            padding: 0.15rem 0.6rem;
            border-radius: 10px;
            font-size: 0.8rem;
            font-weight: normal;
        }

        .findings-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1.5rem;
            font-size: 0.85rem;
        }

        .findings-table thead th {
            background: var(--bg-table);
            color: var(--accent-blue);
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid var(--accent-blue);
            white-space: nowrap;
        }

        .findings-table tbody td {
            padding: 0.65rem 0.75rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }

        .findings-table tbody tr:hover {
            background: rgba(76, 201, 240, 0.05);
        }

        .object-dn {
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 0.75rem;
            word-break: break-all;
            max-width: 250px;
            color: var(--text-secondary);
        }

        .severity-badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical {
            background: rgba(255, 45, 85, 0.2);
            color: var(--severity-critical);
            border: 1px solid var(--severity-critical);
        }

        .severity-badge.high {
            background: rgba(255, 107, 53, 0.2);
            color: var(--severity-high);
            border: 1px solid var(--severity-high);
        }

        .severity-badge.medium {
            background: rgba(255, 193, 7, 0.2);
            color: var(--severity-medium);
            border: 1px solid var(--severity-medium);
        }

        .severity-badge.low {
            background: rgba(76, 201, 240, 0.2);
            color: var(--severity-low);
            border: 1px solid var(--severity-low);
        }

        .severity-badge.informational {
            background: rgba(108, 117, 125, 0.2);
            color: var(--severity-info);
            border: 1px solid var(--severity-info);
        }

        .severity-critical td:first-child {
            border-left: 3px solid var(--severity-critical);
        }
        .severity-high td:first-child {
            border-left: 3px solid var(--severity-high);
        }
        .severity-medium td:first-child {
            border-left: 3px solid var(--severity-medium);
        }
        .severity-low td:first-child {
            border-left: 3px solid var(--severity-low);
        }

        /* Section toolbar */
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
            color: var(--bg-dark);
        }

        /* Protocol audit — donut charts */
        .protocol-audit {
            margin: 2rem 0;
        }

        .protocol-audit h2 {
            color: var(--accent-blue);
            font-size: 1.3rem;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }

        .protocol-audit h3 {
            color: var(--accent-blue);
            font-size: 1.1rem;
            margin: 1.5rem 0 0.5rem 0;
        }

        .chart-row {
            display: flex;
            gap: 3rem;
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
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 1rem;
        }

        .donut-wrapper {
            position: relative;
            width: 160px;
            height: 160px;
            margin: 0 auto 1rem auto;
        }

        .donut-wrapper svg {
            transform: rotate(-90deg);
        }

        .donut-center {
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .donut-center .big {
            font-size: 1.6rem;
            font-weight: 800;
            display: block;
        }

        .donut-center .small {
            font-size: 0.7rem;
            color: var(--text-secondary);
        }

        .chart-legend {
            display: flex;
            justify-content: center;
            gap: 1.2rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
            font-size: 0.8rem;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.35rem;
        }

        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }

        .top-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
            font-size: 0.8rem;
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

        .top-table tbody tr:hover {
            background: rgba(76, 201, 240, 0.05);
        }

        .top-tables-row {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            margin: 1rem 0;
        }

        .top-tables-row > div {
            flex: 1;
            min-width: 280px;
        }

        .footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 3rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.8rem;
        }

        .meta-info {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin: 1rem 0;
            color: var(--text-secondary);
            font-size: 0.85rem;
            flex-wrap: wrap;
        }

        .refs-cell { font-size: 0.75rem; max-width: 220px; word-break: break-all; }
        .refs-cell a { color: var(--accent); text-decoration: none; }
        .refs-cell a:hover { text-decoration: underline; }

        .score-breakdown { margin: 2rem 0; }
        .score-breakdown h2 { margin-bottom: 1rem; }

        @media print {
            body {
                background: white;
                color: #333;
                padding: 1rem;
            }
            .score-card {
                background: #f5f5f5;
                border: 1px solid #ddd;
            }
            .findings-table thead th {
                background: #e0e0e0;
                color: #333;
            }
            .findings-table tbody td {
                border-color: #ddd;
            }
            .section-toolbar {
                display: none;
            }
            .category-section {
                display: block !important;
            }
            .category-section > * {
                display: revert !important;
            }
            details, details[open] {
                display: block !important;
            }
            details > summary {
                list-style: none;
            }
            details > summary::-webkit-details-marker {
                display: none;
            }
            details > *:not(summary) {
                display: block !important;
            }
            .refs-cell a {
                color: #333;
                word-break: break-all;
            }
            .chart-card {
                background: #f5f5f5;
                border: 1px solid #ddd;
            }
        }

        @media (max-width: 768px) {
            body { padding: 1rem; }
            .findings-table { font-size: 0.75rem; }
            .score-section { flex-direction: column; align-items: center; }
        }
    </style>
</head>
<body>

    <div class="header">
        <h1>{{TOOL_NAME}}</h1>
        <div class="subtitle">{{COMPANY_NAME}} &mdash; v{{VERSION}} &mdash; {{DATE}}</div>
    </div>

    <div class="score-section">
        <div class="score-card {{GRADE_CLASS}}">
            <div class="score-value">{{SCORE}}</div>
            <div class="score-label">Score / 100</div>
        </div>
        <div class="score-card {{GRADE_CLASS}}">
            <div class="score-value">{{GRADE}}</div>
            <div class="score-label">Grade</div>
        </div>
        <div class="score-card">
            <div class="score-value" style="color: var(--text-primary);">{{TOTAL_FINDINGS}}</div>
            <div class="score-label">Findings</div>
        </div>
        <div class="score-card">
            <div class="score-value" style="color: var(--text-primary);">{{RULES_EVALUATED}}</div>
            <div class="score-label">Rules Evaluated</div>
        </div>
    </div>

    <div class="severity-summary">
        <div class="severity-pill">
            <span class="severity-dot critical"></span>
            <span>Critical: <strong>{{CRITICAL_COUNT}}</strong></span>
        </div>
        <div class="severity-pill">
            <span class="severity-dot high"></span>
            <span>High: <strong>{{HIGH_COUNT}}</strong></span>
        </div>
        <div class="severity-pill">
            <span class="severity-dot medium"></span>
            <span>Medium: <strong>{{MEDIUM_COUNT}}</strong></span>
        </div>
        <div class="severity-pill">
            <span class="severity-dot low"></span>
            <span>Low: <strong>{{LOW_COUNT}}</strong></span>
        </div>
        <div class="severity-pill">
            <span class="severity-dot info"></span>
            <span>Info: <strong>{{INFO_COUNT}}</strong></span>
        </div>
    </div>

    <hr style="border-color: var(--border); margin: 2rem 0;">

    {{DC_CONNECTIVITY}}

    {{PROTOCOL_AUDIT}}

    {{SCORE_BREAKDOWN}}

    <hr style="border-color: var(--border); margin: 2rem 0;">

    <div class="section-toolbar">
        <button onclick="document.querySelectorAll('.category-section').forEach(d=>d.open=true)">&#9660; Expand All</button>
        <button onclick="document.querySelectorAll('.category-section').forEach(d=>d.open=false)">&#9654; Collapse All</button>
    </div>

    {{CATEGORY_BLOCKS}}

    <div class="footer">
        <p>Generated by <strong>{{TOOL_NAME}}</strong> v{{VERSION}} on {{DATE}}</p>
        <p>Generated by <strong>MATI</strong> — an open-source Active Directory security assessment tool. <a href="https://github.com/yourrepo/MATI" target="_blank">github.com/yourrepo/MATI</a></p>
    </div>

    <script>
    // Force-open all <details> sections before printing
    window.addEventListener('beforeprint', function() {
        document.querySelectorAll('details').forEach(function(d) { d.setAttribute('open', ''); });
    });
    </script>

</body>
</html>
