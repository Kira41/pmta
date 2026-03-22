from __future__ import annotations

import copy
import random
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, jsonify, render_template_string, url_for

app = Flask(__name__)

JOBS_PAGE_HTML = r"""<html lang="en"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Jobs</title>
  <style>
    :root{
      --bg:#0b1020;
      --card: rgba(255,255,255,.06);
      --card2: rgba(255,255,255,.04);
      --border: rgba(255,255,255,.14);
      --text:#fff;
      --muted: rgba(255,255,255,.65);
      --accent:#7aa7ff;
      --good:#35e49a;
      --bad:#ff5e73;
      --warn:#ffc14d;
      --shadow: 0 18px 55px rgba(0,0,0,.35);
      --radius: 16px;
    }
    *{box-sizing:border-box}
    body{font-family:system-ui; margin:0; background:var(--bg); color: var(--text); padding:18px 14px;}
    a{color:var(--accent); text-decoration:none}

    .wrap{max-width: 1200px; margin: 0 auto;}

    .top{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between; margin-bottom:12px;}
    h2{margin:0; font-size: 20px;}
    .sub{margin-top:6px; color:var(--muted); font-size:12px; line-height:1.6; max-width: 760px;}

    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:8px}
    .nav form{display:inline; margin:0;}

    .btn{
      border:1px solid rgba(255,255,255,.14);
      background: rgba(122,167,255,.14);
      color: rgba(255,255,255,.92);
      padding:10px 12px;
      border-radius: 14px;
      cursor:pointer;
      font: inherit;
      font-weight: 800;
      display:inline-flex;
      align-items:center;
      gap:8px;
      text-decoration:none;
    }
    .btn:hover{filter:brightness(1.06)}
    .btn.secondary{background: rgba(255,255,255,.06); font-weight:700;}
    .btn.danger{background: rgba(255,94,115,.14);}
    .btn:disabled{opacity:.55; cursor:not-allowed;}

    .job{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 14px;
      margin-bottom: 12px;
      backdrop-filter: blur(10px);
    }

    .filterToggleBtn{
      position: fixed;
      top: 86px;
      right: 14px;
      z-index: 45;
      border-radius: 999px;
      padding: 11px 12px;
      box-shadow: var(--shadow);
      background: rgba(10,16,34,.95);
      border: 1px solid rgba(255,255,255,.24);
      transition: opacity .2s ease;
    }
    body.filterMenuOpen .filterToggleBtn{ opacity:.92; }

    .filterDrawerBackdrop{
      position: fixed;
      inset: 0;
      background: rgba(3,7,20,.58);
      backdrop-filter: blur(2px);
      z-index: 46;
      opacity: 0;
      pointer-events: none;
      transition: opacity .22s ease;
    }
    .filterDrawer{
      position: fixed;
      top: 0;
      right: 0;
      width: min(380px, 94vw);
      height: 100vh;
      overflow-y: auto;
      z-index: 47;
      transform: translateX(102%);
      transition: transform .24s ease;
      padding: 74px 14px 16px;
      background: linear-gradient(180deg, rgba(10,16,34,.96), rgba(8,13,28,.98));
      border-left: 1px solid var(--border);
      box-shadow: -14px 0 42px rgba(0,0,0,.36);
    }
    body.filterMenuOpen .filterDrawerBackdrop{opacity:1; pointer-events:auto;}
    body.filterMenuOpen .filterDrawer{transform: translateX(0);}

    .filterBar{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border);
      border-radius: 14px;
      padding: 10px 12px;
      margin-bottom: 6px;
      display:grid;
      grid-template-columns: 1fr;
      gap:8px;
      align-items:end;
    }
    .filterCell label{
      display:block;
      font-size:11px;
      color:var(--muted);
      margin-bottom:5px;
      font-weight:700;
      text-transform:uppercase;
      letter-spacing:.3px;
    }
    .filterCell select{
      width:100%;
      border:1px solid rgba(255,255,255,.16);
      background: rgba(255,255,255,.06);
      color: rgba(255,255,255,.9);
      border-radius:10px;
      font: inherit;
      font-size:13px;
      padding:8px 9px;
    }
    .filterCell option{ background:#0b1020; color:#fff; }
    .filterMeta{ grid-column:1 / -1; font-size:12px; color:var(--muted); margin-top:2px; }

    .jobTop{display:flex; gap:12px; flex-wrap:wrap; align-items:flex-start; justify-content:space-between;}
    .titleRow{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
    .mini{color:var(--muted); font-size:12px; line-height:1.55}
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}

    .pill{padding:6px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06); font-size:12px;}
    .pill.good{border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900}
    .pill.bad{border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900}
    .pill.warn{border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900}

    .triageRow{display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-top:8px; max-width:100%;}
    .triageBadge{
      display:inline-flex;
      align-items:center;
      gap:6px;
      max-width:100%;
      border:1px solid rgba(255,255,255,.14);
      background:rgba(255,255,255,.06);
      border-radius:999px;
      padding:4px 9px;
      font-size:11px;
      font-weight:800;
      line-height:1.2;
      color:rgba(255,255,255,.88);
      white-space:nowrap;
      overflow:visible;
      min-width:0;
    }
    .triageBadge .badgeLabel{
      min-width:0;
      overflow:hidden;
      text-overflow:ellipsis;
      white-space:nowrap;
    }
    .triageBadge.good{border-color: rgba(53,228,154,.35); color: var(--good);}
    .triageBadge.warn{border-color: rgba(255,193,77,.35); color: var(--warn);}
    .triageBadge.bad{border-color: rgba(255,94,115,.35); color: var(--bad);}
    .bridgeConnBadge{gap:7px;}
    .statusDot{
      width:9px;
      height:9px;
      border-radius:50%;
      display:inline-block;
      box-shadow:0 0 0 2px rgba(255,255,255,.12);
      flex:0 0 auto;
    }
    .statusDot.good{background: var(--good);}
    .statusDot.bad{background: var(--bad);}

    .kpiWrap{margin-top:12px; border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .kpiRow{display:grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap:8px;}
    .kpiCell{border:1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.03); border-radius:10px; padding:7px 9px;}
    .kpiCell .k{font-size:11px; color: rgba(255,255,255,.62); text-transform:uppercase; letter-spacing:.3px;}
    .kpiCell .v{font-size:16px; font-weight:900; margin-top:2px; display:flex; align-items:center; gap:6px;}
    .kpiCell.kpi-del .k, .kpiCell.kpi-del .v{color:var(--good);}
    .kpiCell.kpi-bnc .k, .kpiCell.kpi-bnc .v{color:var(--bad);}
    .kpiCell.kpi-def .k, .kpiCell.kpi-def .v{color:var(--warn);}
    .kpiCell.kpi-cmp .k, .kpiCell.kpi-cmp .v{color:#ff8bd6;}
    .kpiCell.kpi-sent .k, .kpiCell.kpi-sent .v{color:#fff;}
    .kpiWarn{font-size:12px; color:var(--warn); cursor:help;}
    .ratesRow{display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:8px; margin-top:8px;}
    .rateCell{border:1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.02); border-radius:10px; padding:6px 9px;}
    .rateCell .k{font-size:11px; color: rgba(255,255,255,.62); text-transform:uppercase; letter-spacing:.3px;}
    .rateCell .v{font-size:13px; font-weight:800; margin-top:2px;}
    .qualityMini{margin-top:8px;}
    .qualityMini summary{cursor:pointer; color:rgba(255,255,255,.78); font-size:12px; user-select:none;}
    .qualityLine{margin-top:6px; font-size:12px; color:rgba(255,255,255,.72);}
    @media (max-width: 980px){ .kpiRow{grid-template-columns: repeat(3, minmax(0,1fr));} }
    @media (max-width: 620px){ .kpiRow{grid-template-columns: repeat(2, minmax(0,1fr));} .ratesRow{grid-template-columns: 1fr;} }

    .bars{display:grid; grid-template-columns: 1fr; gap:10px; margin-top: 12px;}
    .barWrap{display:flex; gap:10px; flex-wrap:wrap; align-items:center; justify-content:space-between;}
    .bar{height: 10px; background: rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.14); border-radius:999px; overflow:hidden; width:100%;}
    .bar > div{height:100%; width:0%; background: rgba(122,167,255,.65);} 

    .twoCol{display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin-top:12px;}
    @media (max-width: 980px){ .twoCol{grid-template-columns: 1fr;} }
    .panel{border:1px solid rgba(255,255,255,.10); background: rgba(0,0,0,.10); border-radius: 14px; padding: 10px 12px;}
    .panel h4{margin:0 0 8px; font-size: 13px; color: rgba(255,255,255,.86)}

    .quickIssues{margin-top:10px; font-size:12px; color:var(--warn);}
    .quickIssues:empty{display:none;}
    .more{margin-top:10px;}
    .more > summary{cursor:pointer; user-select:none; font-weight:800; color:rgba(255,255,255,.88);}
    .moreBlock{margin-top:10px;}
    .errorFold{margin-top:12px; margin-left:10px;}
    .errorFold summary{cursor:pointer; color:rgba(255,255,255,.75); font-size:12px;}
    .errorSummaryBox{
      margin-top:8px;
      border:1px solid rgba(255,94,115,.45);
      background: rgba(90,18,32,.36);
      border-radius:10px;
      padding:9px 10px;
      color: rgba(255,206,214,.95);
    }
    .errorSummaryBox:empty{display:none;}
    .sopHeader{
      display:flex;
      align-items:center;
      gap:8px;
      margin:0 0 10px;
      color:rgba(255,255,255,.95);
      font-weight:900;
      letter-spacing:.2px;
      font-size:14px;
    }
    .sopBlock{margin-top:12px; padding:10px; border:1px solid rgba(255,255,255,.1); border-radius:10px; background:rgba(255,255,255,.02);}
    .sopBlock:first-of-type{margin-top:6px;}
    .sopLabel{font-size:12px; font-weight:900; margin-bottom:6px; letter-spacing:.2px;}
    .sopLabel.system{color:#9fd0ff;}
    .sopLabel.provider{color:#c8f5b1;}
    .sopLabel.integrity{color:#ffd9a8;}
    .sopLine{font-size:13px; line-height:1.5; color:rgba(255,255,255,.88);}
    .legacyDiagnosticsBox{
      margin-top:14px;
      padding:12px;
      border:1px solid rgba(255,255,255,.14);
      border-radius:12px;
      background:linear-gradient(180deg, rgba(122,167,255,.12), rgba(122,167,255,.03));
    }
    .legacyDiagnosticsTitle{
      margin:0;
      font-size:13px;
      font-weight:900;
      color:#d5e4ff;
      display:flex;
      align-items:center;
      gap:8px;
    }
    .legacySectionLabel{
      margin-top:10px;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.3px;
      color:rgba(213,228,255,.84);
      font-weight:800;
    }
    .legacyDataLine{
      margin-top:6px;
      padding:8px 10px;
      border:1px solid rgba(255,255,255,.12);
      border-radius:10px;
      background:rgba(0,0,0,.16);
      color:rgba(255,255,255,.9);
      overflow-wrap:anywhere;
    }
    .bridgeSnapshotBox{
      margin-top:12px;
      padding:10px 12px;
      border:1px solid rgba(64,225,173,.35);
      border-radius:10px;
      background:rgba(13,67,51,.26);
      color:#c8ffed;
    }

    /* PMTA Live Panel (Jobs) — clearer layout */
    .pmtaLive{ margin-top:10px; }
    .pmtaCompact{
      margin-top:10px;
      font-size:12px;
      color:rgba(255,255,255,.86);
      border:1px solid rgba(255,255,255,.14);
      background:rgba(0,0,0,.14);
      border-radius:10px;
      padding:8px 10px;
      font-weight:800;
      line-height:1.45;
      overflow-wrap:anywhere;
    }
    .pmtaToggle{ margin-top:8px; }
    .pmtaToggle > summary{ cursor:pointer; user-select:none; color:rgba(255,255,255,.88); font-weight:800; }
    .pmtaGrid{ display:grid; grid-template-columns: repeat(7, minmax(0,1fr)); gap:10px; }
    @media (max-width: 1150px){ .pmtaGrid{ grid-template-columns: repeat(4, minmax(0,1fr)); } }
    @media (max-width: 820px){ .pmtaGrid{ grid-template-columns: repeat(2, minmax(0,1fr)); } }

    .pmtaBox{
      border:1px solid rgba(255,255,255,.12);
      background: rgba(0,0,0,.14);
      border-radius: 14px;
      padding: 10px 12px;
      min-height: 74px;
    }
    .pmtaTitle{
      font-size: 11px;
      letter-spacing: .6px;
      text-transform: uppercase;
      color: rgba(255,255,255,.60);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom: 8px;
      user-select:none;
    }
    .pmtaTitle .tag{font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06);}
    .pmtaTitle .tag.good{ border-color: rgba(53,228,154,.35); color: var(--good); font-weight:900; }
    .pmtaTitle .tag.warn{ border-color: rgba(255,193,77,.35); color: var(--warn); font-weight:900; }
    .pmtaTitle .tag.bad{ border-color: rgba(255,94,115,.35); color: var(--bad); font-weight:900; }

    .pmtaRow{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-top:6px; }
    .pmtaKey{ font-size: 11px; color: rgba(255,255,255,.60); letter-spacing:.4px; text-transform:uppercase; }
    .pmtaVal{
      font-size: 16px;
      font-weight: 950;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      color: rgba(255,255,255,.92);
    }
    .pmtaVal.good{ color: var(--good); }
    .pmtaVal.warn{ color: var(--warn); }
    .pmtaVal.bad{ color: var(--bad); }
    .pmtaBig{ font-size: 22px; font-weight: 1000; letter-spacing: .2px; }
    .pmtaSub{ margin-top:8px; font-size: 11px; color: rgba(255,255,255,.60); line-height: 1.35; word-break: break-word; overflow-wrap:anywhere; }
    .pmtaHint{ margin-top:6px; font-size: 11px; color: rgba(255,255,255,.52); line-height: 1.35; }

    .chunkMeta{
      display:flex;
      flex-wrap:wrap;
      gap:6px;
      margin-top:8px;
      padding:8px;
      border:1px solid rgba(122,167,255,.28);
      border-radius:11px;
      background:linear-gradient(135deg, rgba(122,167,255,.14), rgba(53,228,154,.08));
    }
    .chunkMetaPill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:4px 9px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.2);
      background:rgba(8,14,34,.48);
      font-size:11px;
      color:rgba(255,255,255,.92);
      font-weight:800;
      line-height:1.2;
    }
    .chunkList{display:grid; gap:7px; margin-top:10px;}
    .chunkItem{display:flex; align-items:flex-start; gap:8px; padding:7px 9px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.03); border-radius:10px;}
    .chunkIcon{font-size:13px; line-height:1.2; margin-top:1px;}
    .chunkLabel{font-size:11px; color:rgba(255,255,255,.62); text-transform:uppercase; letter-spacing:.35px;}
    .chunkValue{font-size:12px; color:rgba(255,255,255,.92); font-weight:800; line-height:1.35; overflow-wrap:anywhere;}
    .chunkValue.warn{color:var(--warn);}
    .chunkValue.bad{color:var(--bad);}
    .chunkValue.good{color:var(--good);}
    .chunkNote{margin-top:8px; padding:8px 10px; border-radius:10px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.03);}
    .chunkNoteAdaptive{border-color:rgba(53,228,154,.32); background:rgba(53,228,154,.08);}
    .chunkNoteDomains{margin-top:10px; border-color:rgba(255,152,65,.38); background:rgba(255,152,65,.09);}

    .pmtaBanner{
      border:1px solid rgba(255,255,255,.14);
      border-radius: 14px;
      padding: 10px 12px;
      background: rgba(0,0,0,.16);
      color: rgba(255,255,255,.90);
      font-weight: 800;
      line-height: 1.5;
    }
    .pmtaBanner.good{ border-color: rgba(53,228,154,.35); }
    .pmtaBanner.warn{ border-color: rgba(255,193,77,.35); }
    .pmtaBanner.bad{ border-color: rgba(255,94,115,.35); }

    details.more{margin-top:10px;}
    details.more summary{cursor:pointer; color: rgba(255,255,255,.86); font-weight:900;}

    .moreGrid{display:grid; grid-template-columns: 1.1fr .9fr; gap:10px; margin-top:10px;}
    @media (max-width: 980px){ .moreGrid{grid-template-columns: 1fr;} }

    .smallBar{height:8px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div{height:100%; width:0%; background: rgba(53,228,154,.55);} 

    .outcomesWrap{
      margin-top:8px;
      padding:10px;
      border:1px solid rgba(255,255,255,.10);
      border-radius:12px;
      background: rgba(255,255,255,.03);
    }
    .outcomesGrid{
      display:grid;
      grid-template-columns: repeat(2, minmax(0,1fr));
      gap:8px;
    }
    .outChip{
      border:1px solid rgba(255,255,255,.10);
      border-radius:10px;
      padding:8px 10px;
      background: rgba(0,0,0,.16);
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:8px;
    }
    .outChip .k{font-size:11px; letter-spacing:.5px; text-transform:uppercase; color:rgba(255,255,255,.62);}
    .outChip .v{font-weight:900; font-size:15px;}
    .outChip.del .v{color: var(--good);}
    .outChip.bnc .v{color: var(--bad);}
    .outChip.def .v{color: var(--warn);}
    .outChip.cmp .v{color: #ff8bd6;}
    .outTrend{
      margin-top:10px;
      padding:10px;
      border:1px dashed rgba(255,255,255,.14);
      border-radius:10px;
      background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.01));
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size:12px;
      line-height:1.5;
      color: rgba(255,255,255,.84);
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    .trendHead{ color: rgba(255,255,255,.66); margin-right:8px; font-weight:800; }
    .trendSeg{ display:inline-flex; align-items:center; gap:6px; margin:2px 8px 2px 0; }
    .trendSeg .lbl{ font-weight:900; letter-spacing:.5px; }
    .trendSeg .spark{ font-size:13px; }
    .trendSeg.del .lbl, .trendSeg.del .spark{ color: var(--good); }
    .trendSeg.bnc .lbl, .trendSeg.bnc .spark{ color: var(--bad); }
    .trendSeg.def .lbl, .trendSeg.def .spark{ color: var(--warn); }
    .trendSeg.cmp .lbl, .trendSeg.cmp .spark{ color: #ff8bd6; }
    .outMeta{ margin-top:8px; font-size:11px; color:rgba(255,255,255,.62); }
    @media (max-width: 560px){ .outcomesGrid{ grid-template-columns: 1fr; } }

    table{width:100%; border-collapse:collapse; font-size: 12px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}

    .ok{color:var(--good); font-weight:900}
    .no{color:var(--bad); font-weight:900}

    /* Toast */
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{
      min-width: 280px;
      max-width: 460px;
      background: rgba(0,0,0,.55);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      border-radius: 14px;
      padding: 12px 14px;
      color: rgba(255,255,255,.92);
      font-size: 13px;
      line-height: 1.5;
      animation: pop .18s ease-out;
    }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:900; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }

    .labelTip{ display:inline-flex; align-items:center; gap:6px; }
    .tip{display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:999px;
      border:1px solid rgba(255,255,255,.18); background: rgba(0,0,0,.18); color: rgba(255,255,255,.86);
      font-size: 12px; cursor: help; position: relative; user-select:none}
    .triageBadge .tip{ width:14px; height:14px; font-size:10px; }
    .tip:hover::after{
      content: attr(data-tip);
      position: absolute;
      left: 0;
      top: 24px;
      min-width: 240px;
      max-width: 420px;
      background: rgba(0,0,0,.72);
      border: 1px solid rgba(255,255,255,.18);
      box-shadow: 0 18px 55px rgba(0,0,0,.35);
      backdrop-filter: blur(10px);
      color: rgba(255,255,255,.92);
      padding: 10px 12px;
      border-radius: 14px;
      z-index: 999;
      white-space: normal;
    }
  </style>
</head>
<body>
  <div class="wrap">

    <div class="top">
      <div>
        <h2>Jobs</h2>
        <div class="sub">
          Live monitoring: summary, current chunk, backoff, progress bars, top domains, counters, error histogram, and chunk preflight history.
        </div>
        <div class="nav">
          
            <form method="get" action="/campaign/abac50d078ae">
              <button class="btn secondary" type="submit">← Back to Campaign</button>
            </form>
            <a class="btn secondary" href="/campaigns">📌 Campaigns</a>
          
        </div>
      </div>
      <div class="nav">
        <button class="btn secondary" type="button" id="btnRefreshAll">🔄 Refresh</button>
      </div>
    </div>

    <button class="btn secondary filterToggleBtn" type="button" id="btnToggleFilters">🎛️</button>
    <div class="filterDrawerBackdrop" id="jobsFilterBackdrop"></div>
    <aside class="filterDrawer" id="jobsFilterDrawer" aria-hidden="true">
      <div class="filterBar" id="jobsFilterBar">
        <div class="filterCell">
          <label for="fltStatus" class="labelTip">Status <span class="tip" data-tip="Filter jobs by current execution state (running/done/paused/backoff/stop).">ⓘ</span></label>
          <select id="fltStatus">
            <option value="all">All</option>
            <option value="running">running</option>
            <option value="done">done</option>
            <option value="paused">paused</option>
            <option value="backoff">backoff</option>
            <option value="stop">stopped</option>
          </select>
        </div>
        <div class="filterCell">
          <label for="fltMode" class="labelTip">Mode <span class="tip" data-tip="Show jobs by bridge polling mode: counts or legacy.">ⓘ</span></label>
          <select id="fltMode">
            <option value="all">All</option>
            <option value="counts">counts</option>
            <option value="legacy">legacy</option>
          </select>
        </div>
        <div class="filterCell">
          <label for="fltRisk" class="labelTip">Risk <span class="tip" data-tip="Highlight jobs with health/risk signals such as stale updates or degraded internals.">ⓘ</span></label>
          <select id="fltRisk">
            <option value="all">All</option>
            <option value="internal_degraded">internal degraded</option>
            <option value="deliverability_high">deliverability high</option>
            <option value="stale">stale</option>
          </select>
        </div>
        <div class="filterCell">
          <label for="fltProvider" class="labelTip">Provider <span class="tip" data-tip="Filter by recipient provider bucket (gmail/yahoo/outlook/icloud/other).">ⓘ</span></label>
          <select id="fltProvider">
            <option value="all">All</option>
            <option value="gmail">gmail</option>
            <option value="yahoo">yahoo</option>
            <option value="outlook">outlook</option>
            <option value="icloud">icloud</option>
            <option value="other">other</option>
          </select>
        </div>
        <div class="filterCell">
          <label for="fltSort" class="labelTip">Sort <span class="tip" data-tip="Control card order: newest first, highest risk first, or stalest first.">ⓘ</span></label>
          <select id="fltSort">
            <option value="newest">newest first</option>
            <option value="highest_risk">highest risk first</option>
            <option value="stalest">stalest first</option>
          </select>
        </div>
        <div class="filterMeta" id="filterMeta">Showing all 1 job.</div>
      </div>
    </aside>

    
      
    

    <div class="job" id="jobsFilteredEmpty" style="">
      <div class="mini">No jobs match the selected filters.</div>
    </div>

    <div class="job" id="jobsListEmpty" style="">
      <div class="mini">No jobs yet.</div>
    </div>

  <div class="job" data-jobid="83b5cd63007e" data-created="2026-03-22T10:19:10Z">
        <div class="jobTop">
          <div>
            <div class="titleRow">
              <div style="font-weight:900">Job <code>83b5cd63007e</code></div>
              <div class="pill bad" data-k="status">Status: error</div>
              <div class="pill" data-k="speed">0 epm</div>
              <div class="pill" data-k="eta">ETA —</div>
            </div>
            <div class="triageRow">
              <div class="triageBadge" data-k="badgeMode"><span class="badgeLabel">—</span><span class="tip" data-tip="Bridge mode not available yet for this job.">ⓘ</span></div>
              <div class="triageBadge" data-k="badgeFreshness"><span class="badgeLabel">—</span><span class="tip" data-tip="Freshness signal: how recent accounting or legacy ingestion updates are for this job.">ⓘ</span></div>
              <div class="triageBadge good" data-k="badgeHealth"><span class="badgeLabel">OK (0)</span><span class="tip" data-tip="Internal health checks are clean (no bridge/runtime failure counters).">ⓘ</span></div>
              <div class="triageBadge" data-k="badgeRisk"><span class="badgeLabel">RISK —</span><span class="tip" data-tip="Deliverability risk derived from bounce, complaint, and deferred rates.">ⓘ</span></div>
              <div class="triageBadge bridgeConnBadge good" data-k="badgeBridgeConn" title="Bridge↔Shiva connected"><span class="statusDot good" aria-hidden="true"></span><span>Bridge↔Shiva connected</span><span class="tip" data-tip="Real-time bridge transport status between PMTA accounting bridge and Shiva receiver. Current endpoint is not available yet.">ⓘ</span></div>
              <div class="triageBadge" data-k="badgeIntegrity" style=""><span class="badgeLabel">INTEGRITY</span><span class="tip" data-tip="Data integrity counters are clean.">ⓘ</span></div>
            </div>
            <div class="mini">Created: <span class="muted">2026-03-22T10:19:10Z</span></div>
            <div class="mini" data-k="alerts">Quick issues: ❌ abandoned chunks</div>
          </div>

          <div class="nav" style="margin-top:0">
            <a class="btn secondary" href="/job/83b5cd63007e">Open</a>
            <button class="btn secondary" type="button" data-action="pause" disabled="">⏸ Pause</button>
            <button class="btn secondary" type="button" data-action="resume" disabled="">▶ Resume</button>
            <button class="btn danger" type="button" data-action="stop" disabled="">⛔ Stop</button>
            <button class="btn danger" type="button" data-action="delete">🗑 Delete</button>
          </div>
        </div>

        <!-- 1) Compact KPI + rates -->
        <div class="kpiWrap">
          <div class="kpiRow">
            <div class="kpiCell kpi-sent"><div class="k">Sent</div><div class="v"><span data-k="sent">0</span></div></div>
            <div class="kpiCell"><div class="k">Pending</div><div class="v"><span data-k="pending">0</span><span class="kpiWarn" data-k="pendingWarn" style="" title="Pending was clamped to 0 because Sent is lower than PMTA outcomes.">⚠</span></div></div>
            <div class="kpiCell kpi-del"><div class="k">Del</div><div class="v"><span data-k="delivered">0</span></div></div>
            <div class="kpiCell kpi-bnc"><div class="k">Bnc</div><div class="v"><span data-k="bounced">0</span></div></div>
            <div class="kpiCell kpi-def"><div class="k">Def</div><div class="v"><span data-k="deferred">0</span></div></div>
            <div class="kpiCell kpi-cmp"><div class="k">Cmp</div><div class="v"><span data-k="complained">0</span></div></div>
          </div>
          <div class="ratesRow">
            <div class="rateCell"><div class="k">Bounce %</div><div class="v" data-k="rateBounce">—</div></div>
            <div class="rateCell"><div class="k">Complaint %</div><div class="v" data-k="rateComplaint">—</div></div>
            <div class="rateCell"><div class="k">Deferred %</div><div class="v" data-k="rateDeferred">—</div></div>
          </div>

          <div class="panel" style="margin-top:10px;">
            <h4>PMTA Live Panel</h4>
            <div class="pmtaLive" data-k="pmtaLine">
        <div class="pmtaGrid">
          <div class="pmtaBox"><div class="pmtaTitle"><span>Spool</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Total recipients/messages currently held by PMTA spool.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Queue</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Recipients/messages still queued to be delivered.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Connections</span></div><div class="pmtaHint">Live SMTP sessions used for inbound/outbound traffic.</div><div class="pmtaRow"><span class="pmtaKey">SMTP In</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">SMTP Out</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Total</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last minute</span></div><div class="pmtaHint">Recent PMTA throughput over the last 60 seconds.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / minute</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last hour</span></div><div class="pmtaHint">Rolling traffic totals for the previous 60 minutes.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / hour</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Top queues</span></div><div class="pmtaHint">Queues with the highest recipient backlog and latest queue errors.</div><div class="pmtaSub">0=0</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Time</span></div><div class="pmtaHint">Timestamp of the latest PMTA snapshot used for this panel.</div><div class="pmtaSub">2026-03-22T10:19:41Z</div></div>
        </div>
      </div>
            <div class="mini" style="margin-top:6px" data-k="pmtaNote">Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.</div>
            <div class="chunkMeta" style="margin-top:6px" data-k="pmtaDiag"><span class="chunkMetaPill">Diag: —</span></div>
            <div class="mini" style="margin-top:8px"><b>Error summary</b></div>
            <div class="mini errorSummaryBox" data-k="pmtaErrorSummary" style="display: none;"></div>
          </div>

          <details class="qualityMini">
            <summary>Quality</summary>
            <div class="qualityLine">Final-fail: <span data-k="failed">0</span> · Skipped: <span data-k="skipped">0</span> · Invalid: <span data-k="invalid">0</span> · Total: <span data-k="total">1</span></div>
          </details>
        </div>

        <!-- 4) Progress bars -->
        <div class="bars">
          <div class="panel">
            <h4>Progress</h4>
            <div class="mini" data-k="progressText">Send progress: 0% (0/1)</div>
            <div class="bar"><div data-k="barSend" style="width: 0%;"></div></div>
            <div class="mini" style="margin-top:8px" data-k="chunksText">Chunks: 1/1 done · backoff_events=0 · abandoned=1</div>
            <div class="mini" data-k="attemptsText" style="">—</div>
            <div class="bar"><div data-k="barChunks" style="width: 100%;"></div></div>
            <div class="mini" style="margin-top:8px" data-k="domainsText">Domains: 0% (0/1)</div>
            <div class="bar"><div data-k="barDomains" style="width: 0%;"></div></div>
          </div>
        </div>

        <div class="quickIssues" data-k="quickIssues">Quick issues: ❌ abandoned chunks</div>

        <details class="more" open="">
          <summary>More details</summary>
          <div class="moreBlock twoCol">
            <!-- 2) Current chunk + 3) backoff info -->
            <div class="panel">
              <h4>Current chunk</h4>
              <div class="mini">Current send settings + top active domains in this running chunk.</div>
              <div class="mini" data-k="chunkLine"><div class="mini">—</div></div>
              <div class="mini" data-k="chunkDomains"><div class="mini chunkNote chunkNoteDomains">🔥 Top active domains: —</div></div>
            </div>
            <div class="panel">
              <h4>Backoff</h4>
              <div class="mini">Latest retry event when PMTA/provider pressure slows delivery.</div>
              <div class="mini" data-k="backoffLine">—</div>
            </div>
          </div>

          <div class="panel moreBlock">
            <h4>Outcomes (PMTA accounting)</h4>
            <div class="outcomesWrap" data-k="outcomes">
        <div class="outcomesGrid">
          <div class="outChip del"><span class="k">Delivered</span><span class="v">0</span></div>
          <div class="outChip bnc"><span class="k">Bounced</span><span class="v">0</span></div>
          <div class="outChip def"><span class="k">Deferred</span><span class="v">0</span></div>
          <div class="outChip cmp"><span class="k">Complained</span><span class="v">0</span></div>
        </div>
        <div class="outMeta">Pending (sent - final outcomes): <b>0</b> · PMTA queue now: <b>0</b></div>
        <div class="outMeta">Last accounting update: —</div>
      </div>
            <div class="outTrend" data-k="outcomeTrend">Trend · —</div>
          </div>

          <div class="moreGrid moreBlock">

            <!-- 5) Top domains -->
            <div class="panel">
              <h4 data-k="domainsPanelTitle">Top providers</h4>
              <div class="mini" data-k="topDomains">Gmail: <b>0</b> · Yahoo: <b>0</b> · Outlook: <b>0</b> · iCloud: <b>0</b> · Other: <b>1</b></div>
              <div class="mini" style="margin-top: 10px; display: none;"><b>Domain progress (bars)</b></div>
              <div data-k="topDomainsBars"><div style="margin-top:10px"><div class="mini"><b>Gmail</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Yahoo</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Outlook</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>iCloud</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Other</b> · 1</div><div class="smallBar"><div style="width:100%"></div></div></div></div>
            </div>

            <div class="panel">
              <h4 class="sopHeader">📌 System / Provider / Integrity</h4>

              <div class="sopBlock">
              <div class="sopLabel system">🖥️ System / Internal</div>
              <div class="sopLine" data-k="systemSummary">🔗 Bridge failures: <b>0</b> · ⏱️ Last bridge success: <b>0m ago</b> · ⚙️ Runtime internal errors: <b>0</b> · 💾 DB write failures: <b>0</b></div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="systemDetails">—</div>
              </details>
              </div>

              <div class="sopBlock">
              <div class="sopLabel provider">📬 Provider / Deliverability</div>
              <div class="sopLine" data-k="providerSummary">✅ Delivered: <b>0</b> (—) · ⏳ Deferred: <b>0</b> (—) · ❌ Bounced: <b>0</b> (—) · 📢 Complained: <b>0</b> (—)</div>
              <div class="sopLine" style="margin-top:6px" data-k="providerBreakdown">🌐 Provider/domain breakdown: —</div>
              <div class="sopLine" style="margin-top:6px" data-k="providerReasons">🧠 Top reason buckets: —</div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="providerDetails">—</div>
              </details>
              </div>

              <div class="sopBlock">
              <div class="sopLabel integrity">🗂️ Data Integrity / Mapping</div>
              <div class="sopLine" data-k="integritySummary">♻️ duplicates_dropped: <b>0</b> · 🔎 job_not_found: <b>0</b> · 🧾 missing_fields: <b>0</b> · 💽 db_write_failures: <b>0</b></div>
              <details class="errorFold">
                <summary>View details</summary>
                <div class="mini" style="margin-top:8px" data-k="integrityDetails">—</div>
              </details>
              </div>

              <div class="legacyDiagnosticsBox">
                <div class="legacyDiagnosticsTitle">📄 Legacy quality + errors (unchanged data)</div>
                <div class="legacySectionLabel">📊 Quality counters</div>
                <div class="mini legacyDataLine" data-k="counters">safe_total=0 · safe_invalid=0 · invalid_filtered=0 · skipped=0 · backoff_events=0 · abandoned_chunks=1 · paused=no · stop_requested=no</div>
                <div class="legacySectionLabel">🚨 Error type</div>
                <div class="mini legacyDataLine" data-k="errorTypes">—</div>
                <div class="legacySectionLabel">⚠️ Error summary</div>
                <div class="mini legacyDataLine" data-k="lastErrors">—</div>
                <div class="mini legacyDataLine" data-k="lastErrors2">—</div>
                <div class="mini legacyDataLine" data-k="internalErrors">—</div>
              </div>
              <div class="bridgeSnapshotBox">
                <div class="legacySectionLabel" style="margin-top:0">🌉 Data source: Bridge snapshot</div>
                <div class="mini legacyDataLine" style="margin-top:8px" data-k="bridgeReceiver">Data source: <b>Bridge snapshot</b><br>Last poll success: <b>2026-03-22T12:33:05Z (just now)</b><br>Last accounting update: <b>—</b></div>
              </div>
            </div>

          </div>

          <!-- 8) Preflight history per chunk -->
          <div class="panel" style="margin-top:10px">
            <h4>Chunk preflight</h4>
            <div class="mini" style="margin-top:6px"><b>Active / Live chunk</b></div>
            <div style="overflow:auto; margin-top:8px">
              <table>
                <thead>
                  <tr>
                    <th>Chunk</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Sender mail</th>
                    <th>Receiver domain</th>
                    <th>Spam</th>
                    <th>Blacklist</th>
                  </tr>
                </thead>
                <tbody data-k="chunkLive"><tr><td colspan="7" class="mini">No active chunk right now.</td></tr></tbody>
              </table>
            </div>

            <div class="mini" style="margin-top:10px"><b>History chunk (last 12)</b></div>
            <div style="overflow:auto; margin-top:8px">
              <table>
                <thead>
                  <tr>
                    <th>Chunk</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Sender mail</th>
                    <th>Receiver domain</th>
                    <th>Spam</th>
                    <th>Blacklist</th>
                    <th>Attempt</th>
                    <th>Next retry</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody data-k="chunkHist"><tr><td>2</td><td>abandoned</td><td>1</td><td title="welcome@101crossroadsstudio.com">welcome@101crossroadsstudio.co…</td><td>srv1.mail-tester.com</td><td>-1.90</td><td title="domain:101crossroadsstudio.com=&gt;dbl.spamhaus.org">domain:101crossroadsstudio.com…</td><td><b>0</b></td><td><span title="">—</span></td><td title="preflight_blocked: blacklist">preflight_blocked: blacklist</td></tr></tbody>
              </table>
            </div>
          </div>
        </details>

      </div></div>

  <div class="toast-wrap" id="toastWrap"></div>

<script>
  const esc = (s) => (s ?? '').toString().replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
  const escAttr = (s) => esc(s).replaceAll('"','&quot;');

  function badgeWithTip(label, tip){
    const safeLabel = esc(label || '—');
    const safeTip = escAttr(tip || '—');
    return `<span class="badgeLabel">${safeLabel}</span><span class="tip" data-tip="${safeTip}">ⓘ</span>`;
  }

  function toast(title, msg, kind){
    const wrap = document.getElementById('toastWrap');
    const div = document.createElement('div');
    div.className = `toast ${kind || 'warn'}`;
    const safeMsg = esc(msg).split(/\r?\n/).join("<br>");
    div.innerHTML = `<div class="t">${esc(title)}</div><div>${safeMsg}</div>`;
    wrap.appendChild(div);
    setTimeout(() => {
      div.style.opacity = '0';
      div.style.transform = 'translateY(6px)';
      div.style.transition = 'all .22s ease';
      setTimeout(()=>div.remove(), 260);
    }, 3600);
  }

  function qk(root, key){
    return root.querySelector(`[data-k="${key}"]`);
  }

  function pct(n,d){
    const nn = Number(n||0), dd = Number(d||0);
    return dd ? Math.min(100, Math.round((nn/dd)*100)) : 0;
  }

  function fmtEta(sec){
    if(sec === null || sec === undefined) return 'ETA —';
    const s = Math.max(0, Number(sec||0));
    if(!isFinite(s)) return 'ETA —';
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = Math.floor(s % 60);
    if(h > 0) return `ETA ${h}h ${m}m`;
    if(m > 0) return `ETA ${m}m ${ss}s`;
    return `ETA ${ss}s`;
  }

  function tsToMs(ts){
    const s = (ts || '').toString().trim();
    if(!s) return null;
    const n = Date.parse(s);
    return Number.isFinite(n) ? n : null;
  }

  function ageMin(ts){
    const ms = tsToMs(ts);
    if(ms === null) return null;
    return Math.max(0, Math.floor((Date.now() - ms) / 60000));
  }

  function riskBadgeClass(level){
    const lv = (level || '').toString().toLowerCase();
    if(lv === 'low') return 'triageBadge good';
    if(lv === 'med') return 'triageBadge warn';
    if(lv === 'high') return 'triageBadge bad';
    return 'triageBadge';
  }

  function healthBadgeClass(ok){
    if(ok === true) return 'triageBadge good';
    if(ok === false) return 'triageBadge bad';
    return 'triageBadge';
  }

  function computeDeliverabilityRisk(j){
    const sent = Number(j.sent || 0);
    const delivered = Number(j.delivered || 0);
    const bounced = Number(j.bounced || 0);
    const complained = Number(j.complained || 0);
    const deferred = Number(j.deferred || 0);
    if(sent <= 0) return '—';
    const bRate = bounced / sent;
    const cRate = complained / sent;
    const dRate = deferred / sent;
    if(bRate >= 0.12 || cRate >= 0.01 || (delivered <= 0 && sent >= 30)) return 'HIGH';
    if(bRate >= 0.05 || cRate >= 0.003 || dRate >= 0.2) return 'MED';
    return 'LOW';
  }


  function normalizeJobStatus(j){
    const raw = (j && j.status ? j.status : '').toString().trim().toLowerCase();
    if(raw === 'running' || raw === 'done' || raw === 'paused' || raw === 'backoff') return raw;
    if(raw === 'stop' || raw === 'stopped') return 'stop';
    return 'other';
  }

  function normalizeBridgeMode(j){
    const raw = (j && j.bridge_mode ? j.bridge_mode : 'counts').toString().trim().toLowerCase();
    if(raw === 'legacy') return 'legacy';
    if(raw === 'counts') return 'counts';
    return 'counts';
  }

  function freshnessMinutes(j){
    const mode = normalizeBridgeMode(j);
    if(mode === 'counts'){
      return ageMin(j.accounting_last_update_ts || j.accounting_last_ts);
    }
    const lagSecRaw = Number(j && j.ingestion_lag_seconds);
    if(Number.isFinite(lagSecRaw) && lagSecRaw >= 0){
      return Math.floor(lagSecRaw / 60);
    }
    return ageMin(j.ingestion_last_event_ts || j.accounting_last_ts);
  }

  function hasInternalDegraded(j){
    const failureCount = Number(j && j.bridge_failure_count);
    const failN = Number.isFinite(failureCount) ? failureCount : Number(j && j.internal_health_failures || 0);
    return Number.isFinite(failN) && failN > 0;
  }

  function hasDeliverabilityHigh(j){
    return computeDeliverabilityRisk(j) === 'HIGH';
  }

  function isStaleJob(j){
    const mode = normalizeBridgeMode(j);
    const mins = freshnessMinutes(j);
    if(mins === null || !Number.isFinite(mins)) return false;
    return mode === 'legacy' ? mins > 15 : mins > 10;
  }

  function providerBucketFromDomain(domain){
    const d = (domain || '').toString().trim().toLowerCase();
    if(!d) return 'other';
    if(d.includes('gmail.') || d.includes('googlemail.')) return 'gmail';
    if(d.includes('yahoo.') || d.includes('ymail.') || d.includes('rocketmail.')) return 'yahoo';
    if(d.includes('outlook.') || d.includes('hotmail.') || d.includes('live.') || d.includes('msn.')) return 'outlook';
    if(d.includes('icloud.') || d.includes('me.com') || d.includes('mac.com')) return 'icloud';
    return 'other';
  }

  function detectProviderBucket(j){
    const weighted = {};
    const add = (dom, w) => {
      const b = providerBucketFromDomain(dom);
      weighted[b] = Number(weighted[b] || 0) + Math.max(0, Number(w || 0));
    };
    const plan = (j && j.domain_plan) || {};
    for(const [dom, count] of Object.entries(plan)) add(dom, count);
    if(!Object.keys(plan).length){
      const host = (j && j.smtp_host ? j.smtp_host : '').toString().trim().toLowerCase();
      if(host) add(host, 1);
    }
    let best = 'other';
    let bestW = -1;
    for(const [k,v] of Object.entries(weighted)){
      if(v > bestW){
        best = k;
        bestW = v;
      }
    }
    return best;
  }

  function riskRank(j){
    if(hasInternalDegraded(j)) return 3;
    if(hasDeliverabilityHigh(j)) return 2;
    if(isStaleJob(j)) return 1;
    return 0;
  }

  function renderTriageBadges(card, j){
    const modeRaw = (j.bridge_mode || '—').toString().trim().toLowerCase();
    const isCounts = modeRaw === 'counts';
    const isLegacy = modeRaw === 'legacy';

    const modeEl = qk(card, 'badgeMode');
    if(modeEl){
      const modeLabel = isCounts ? 'COUNTS' : (isLegacy ? 'LEGACY' : '—');
      const modeTip = isCounts
        ? 'Bridge polling mode uses aggregated accounting counters (fast/low overhead).'
        : (isLegacy
          ? 'Bridge polling mode uses legacy event stream with ingestion lag tracking.'
          : 'Bridge mode not available yet for this job.');
      modeEl.innerHTML = badgeWithTip(modeLabel, modeTip);
      modeEl.className = 'triageBadge';
    }

    const freshEl = qk(card, 'badgeFreshness');
    if(freshEl){
      let txt = '—';
      let cls = 'triageBadge';
      if(isCounts){
        const mins = ageMin(j.accounting_last_update_ts || j.accounting_last_ts);
        if(mins === null){
          txt = 'acct: —';
        }else if(mins > 10){
          txt = `STALE: ${mins}m`;
          cls = 'triageBadge warn';
        }else{
          txt = `acct: ${mins}m ago`;
          cls = 'triageBadge good';
        }
      }else if(isLegacy){
        const lagSecRaw = Number(j.ingestion_lag_seconds);
        const mins = Number.isFinite(lagSecRaw) && lagSecRaw >= 0
          ? Math.floor(lagSecRaw / 60)
          : ageMin(j.ingestion_last_event_ts || j.accounting_last_ts);
        if(mins === null){
          txt = 'lag: —';
        }else if(mins <= 1){
          txt = 'caught up';
          cls = 'triageBadge good';
        }else{
          txt = `lag: ${mins}m`;
          cls = mins > 15 ? 'triageBadge warn' : 'triageBadge';
        }
      }
      freshEl.innerHTML = badgeWithTip(txt, 'Freshness signal: how recent accounting or legacy ingestion updates are for this job.');
      freshEl.className = cls;
    }

    const failureCount = Number(j.bridge_failure_count);
    const failN = Number.isFinite(failureCount) ? failureCount : Number(j.internal_health_failures || 0);
    const healthEl = qk(card, 'badgeHealth');
    if(healthEl){
      const known = Number.isFinite(failN);
      const ok = known ? failN <= 0 : null;
      healthEl.className = healthBadgeClass(ok);
      if(known){
        const failures = Math.max(0, Math.floor(failN));
        const label = ok ? 'OK (0)' : `DEGRADED (${failures})`;
        const tip = ok
          ? 'Internal health checks are clean (no bridge/runtime failure counters).'
          : `Internal health degraded: ${failures} bridge/runtime failures were detected.`;
        healthEl.innerHTML = badgeWithTip(label, tip);
      }else{
        healthEl.innerHTML = badgeWithTip('—', 'Internal health state is not available yet.');
      }
    }

    const risk = computeDeliverabilityRisk(j);
    const riskEl = qk(card, 'badgeRisk');
    if(riskEl){
      riskEl.className = riskBadgeClass(risk);
      riskEl.innerHTML = badgeWithTip(`RISK ${risk}`, 'Deliverability risk derived from bounce, complaint, and deferred rates.');
    }

    renderBridgeConnectionBadge(card, state.latestBridgeState);

    const dup = Number(j.duplicates_dropped || 0);
    const jnf = Number(j.job_not_found || 0);
    const dbf = Number(j.db_write_failures || 0);
    const miss = Number(j.missing_fields || 0);
    const hasIntegrity = (dup + jnf + dbf + miss) > 0;
    const intEl = qk(card, 'badgeIntegrity');
    if(intEl){
      intEl.style.display = hasIntegrity ? 'inline-flex' : 'none';
      intEl.className = hasIntegrity ? 'triageBadge bad' : 'triageBadge';
      const integrityTotal = dup + jnf + dbf + miss;
      const integrityTip = hasIntegrity
        ? `Data integrity issues found: duplicates=${dup}, job_not_found=${jnf}, missing_fields=${miss}, db_write_failures=${dbf}.`
        : 'Data integrity counters are clean.';
      intEl.innerHTML = badgeWithTip(hasIntegrity ? `INTEGRITY (${integrityTotal})` : 'INTEGRITY', integrityTip);
    }
  }

  function renderBridgeConnectionBadge(card, bridgeState){
    const bridgeEl = qk(card, 'badgeBridgeConn');
    if(!bridgeEl) return;
    const connected = !!(bridgeState && bridgeState.connected === true);
    const label = connected ? 'Bridge↔Shiva connected' : 'Bridge↔Shiva disconnected';
    const endpoint = (
      (bridgeState && (bridgeState.last_req_url || bridgeState.pull_url_masked || bridgeState.bridge_base_url)) || ''
    ).toString().trim();
    const endpointTip = endpoint
      ? ` Current endpoint: ${endpoint}`
      : ' Current endpoint is not available yet.';
    const tip = `Real-time bridge transport status between PMTA accounting bridge and Shiva receiver.${endpointTip}`;
    bridgeEl.className = `triageBadge bridgeConnBadge ${connected ? 'good' : 'bad'}`;
    bridgeEl.innerHTML = `<span class="statusDot ${connected ? 'good' : 'bad'}" aria-hidden="true"></span><span>${esc(label)}</span><span class="tip" data-tip="${esc(tip)}">ⓘ</span>`;
    bridgeEl.title = endpoint ? `${label} · ${endpoint}` : label;
  }

  function statusPillClass(st){
    const s = (st||'').toString().toLowerCase();
    if(s === 'done') return 'pill good';
    if(s === 'running') return 'pill good';
    if(s === 'paused') return 'pill warn';
    if(s === 'backoff') return 'pill warn';
    if(s === 'stopped') return 'pill warn';
    if(s === 'error') return 'pill bad';
    return 'pill';
  }

  const state = {
    lastStatus: {},
    lastBackoff: {},
    lastAbandoned: {},
    lastFailed: {},
    lastAdaptive: {},
    lastRoute: {},
    lastPmtaMonitor: {},
    lastJobPayload: {},
    latestBridgeState: null,
    filters: {
      status: 'all',
      mode: 'all',
      risk: 'all',
      provider: 'all',
      sort: 'newest',
    },
  };

  async function controlJob(jobId, action){
    const reason = action === 'stop' ? prompt('Stop reason (optional):') : '';
    try{
      const r = await fetch(`/api/job/${jobId}/control`, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({action, reason: reason || ''})
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        toast('Job control', `Job ${jobId}: ${action} OK`, 'good');
      }else{
        toast('Job control failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){
      toast('Job control failed', e?.toString?.() || 'Unknown error', 'bad');
    }
  }

  async function deleteJob(jobId, card){
    const ok = confirm(`Delete job ${jobId}?
This will remove it from Jobs history.`);
    if(!ok) return;
    try{
      const r = await fetch(`/api/job/${jobId}/delete`, { method:'POST' });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        toast('Job deleted', `Job ${jobId} deleted.`, 'good');
        if(card) card.remove();
        cards = cards.filter(x => x !== card);
        applyFiltersAndSort();
      }else{
        toast('Delete failed', (j && (j.error||j.detail)) ? (j.error||j.detail) : ('HTTP '+r.status), 'bad');
      }
    }catch(e){
      toast('Delete failed', e?.toString?.() || 'Unknown error', 'bad');
    }
  }

  function renderTopDomains(card, j){
    const plan = j.domain_plan || {};
    const sent = j.domain_sent || {};
    const failed = j.domain_failed || {};
    const currDom = j.current_chunk_domains || {};

    const pmtaDom = j.pmta_domains || {};
    const pmtaOk = !!pmtaDom.ok;
    const pmtaMap = pmtaDom.domains || {};

    const entries = Object.entries(plan).map(([dom, p]) => {
      const pp = Number(p||0);
      const ss = Number(sent[dom]||0);
      const ff = Number(failed[dom]||0);
      const done = ss + ff;
      return {dom, pp, ss, ff, done, pct: pct(done, pp), active: (dom in currDom)};
    }).sort((a,b)=>b.pp - a.pp).slice(0,10);

    const totalRecipients = Number(j.total || 0);
    const domainsCount = Object.keys(plan).length;
    const showProviders = (totalRecipients <= 50) || (domainsCount <= 5);

    const titleEl = qk(card, 'domainsPanelTitle');
    const elLine = qk(card,'topDomains');
    const elBars = qk(card,'topDomainsBars');
    const barsLabelEl = elBars ? elBars.previousElementSibling : null;

    function providerForDomain(dom){
      const d = (dom || '').toString().trim().toLowerCase();
      if(!d) return 'Other';

      if(
        d === 'gmail.com' || d.endsWith('.gmail.com') ||
        d === 'googlemail.com' || d.endsWith('.googlemail.com')
      ) return 'Gmail';

      if(
        d === 'yahoo.com' || d.endsWith('.yahoo.com') ||
        d.endsWith('.yahoo.co.jp') ||
        d === 'ymail.com' || d.endsWith('.ymail.com') ||
        d === 'rocketmail.com' || d.endsWith('.rocketmail.com') ||
        d === 'yahoo.co.jp'
      ) return 'Yahoo';

      if(
        d === 'outlook.com' || d.endsWith('.outlook.com') ||
        d === 'hotmail.com' || d.endsWith('.hotmail.com') ||
        d === 'live.com' || d.endsWith('.live.com') ||
        d === 'msn.com' || d.endsWith('.msn.com') ||
        d === 'passport.com' || d.endsWith('.passport.com')
      ) return 'Outlook';

      if(
        d === 'icloud.com' || d.endsWith('.icloud.com') ||
        d === 'me.com' || d.endsWith('.me.com') ||
        d === 'mac.com' || d.endsWith('.mac.com')
      ) return 'iCloud';

      return 'Other';
    }

    function renderProviderBreakdown(){
      const buckets = {Gmail: 0, Yahoo: 0, Outlook: 0, iCloud: 0, Other: 0};
      const hasPlan = Object.keys(plan).length > 0;
      if(!hasPlan){
        if(elLine) elLine.textContent = '—';
        if(elBars) elBars.innerHTML = '';
        if(titleEl) titleEl.textContent = 'Top providers';
        if(barsLabelEl) barsLabelEl.style.display = 'none';
        return;
      }

      for(const [dom, rawCount] of Object.entries(plan)){
        const cnt = Number(rawCount || 0);
        const provider = providerForDomain(dom);
        buckets[provider] = Number(buckets[provider] || 0) + Math.max(0, cnt);
      }
      const ordered = ['Gmail', 'Yahoo', 'Outlook', 'iCloud', 'Other'].map(name => ({
        name,
        count: Number(buckets[name] || 0)
      }));

      if(titleEl) titleEl.textContent = 'Top providers';
      if(barsLabelEl) barsLabelEl.style.display = 'none';

      if(elLine){
        elLine.innerHTML = ordered.map(x => `${x.name}: <b>${x.count}</b>`).join(' · ');
      }
      if(elBars){
        const maxCount = Math.max(1, ...ordered.map(x => x.count));
        elBars.innerHTML = ordered.map(x => {
          const width = Math.round((x.count / maxCount) * 100);
          return `<div style="margin-top:10px">`+
            `<div class="mini"><b>${x.name}</b> · ${x.count}</div>`+
            `<div class="smallBar"><div style="width:${width}%"></div></div>`+
          `</div>`;
        }).join('');
      }
    }

    if(!entries.length){
      if(elLine) elLine.textContent = '—';
      if(elBars) elBars.innerHTML = '';
      if(titleEl) titleEl.textContent = showProviders ? 'Top providers' : 'Top domains (Top 10)';
      if(barsLabelEl) barsLabelEl.style.display = showProviders ? 'none' : '';
      return;
    }

    if(showProviders){
      renderProviderBreakdown();
      return;
    }

    if(titleEl) titleEl.textContent = 'Top domains (Top 10)';
    if(barsLabelEl) barsLabelEl.style.display = '';

    if(elLine){
      elLine.innerHTML = entries.map(x => {
        const flag = x.active ? ' 🔥' : '';
        const pm = pmtaMap[x.dom] || {};
        const q = (pm && pm.queued !== undefined && pm.queued !== null) ? pm.queued : '—';
        const d = (pm && pm.deferred !== undefined && pm.deferred !== null) ? pm.deferred : '—';
        const a = (pm && pm.active !== undefined && pm.active !== null) ? pm.active : '—';
        const pmInfo = (pmtaOk && (x.dom in pmtaMap)) ? ` · pmta(q=${q} def=${d} act=${a})` : '';
        return `${esc(x.dom)}: <span class="ok">${x.ss}</span>/<b>${x.pp}</b> (final-fail <span class="no">${x.ff}</span>)${flag}${pmInfo}`;
      }).join('<br>');
    }

    if(elBars){
      elBars.innerHTML = entries.map(x => {
        const bar = `<div class="smallBar"><div style="width:${x.pct}%"></div></div>`;
        return `<div style="margin-top:10px">`+
          `<div class="mini"><b>${esc(x.dom)}</b> · ${x.done}/${x.pp} (${x.pct}%)${x.active ? ' · active' : ''}</div>`+
          `${bar}`+
        `</div>`;
      }).join('');
    }
  }

  function renderErrorTypes(card, j){
    const ec = j.accounting_error_counts || {};
    const entries = Object.entries(ec).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0));
    const el = qk(card,'errorTypes');
    if(!el){ return; }

    const labels = {
      accepted: '2XX accepted',
      temporary_error: '4XX temporary',
      blocked: '5XX blocked'
    };

    const rawErrors = Array.isArray(j.accounting_last_errors) ? j.accounting_last_errors : [];
    const onlyErrors = rawErrors.filter(x => (x && x.kind !== 'accepted'));
    const latestError = onlyErrors.length ? onlyErrors[onlyErrors.length - 1] : null;
    const bouncedN = Number(j.bounced || 0);
    const deferredN = Number(j.deferred || 0);
    const complainedN = Number(j.complained || 0);
    const hasOutcomeFailures = (bouncedN + deferredN + complainedN) > 0;

    function errorSignature(detail){
      const txt = (detail || '').toString();
      const m = txt.match(/\b([245]\.\d\.\d{1,3})\b(?:\s*\(([^)]+)\))?/i);
      if(m){
        const code = (m[1] || '').trim();
        const reason = (m[2] || '').trim();
        return reason ? `${code} (${reason})` : code;
      }
      const smtp = txt.match(/\b([245]\d\d)\b/);
      if(smtp) return smtp[1];
      return txt ? txt.slice(0, 120) : 'unknown';
    }

    const sigMap = new Map();
    for(const x of onlyErrors){
      const sig = errorSignature(x.detail);
      if(!sigMap.has(sig)) sigMap.set(sig, {count: 0, sample: x});
      const row = sigMap.get(sig);
      row.count += 1;
    }
    const topSig = Array.from(sigMap.entries()).sort((a,b)=>b[1].count-a[1].count)[0] || null;

    if(!entries.length && !topSig && !latestError){
      if(hasOutcomeFailures){
        const estBlocked = Math.max(0, bouncedN + complainedN);
        const estTemp = Math.max(0, deferredN);
        const parts = [];
        parts.push(`Latest code: <b>${estBlocked > 0 ? '5XX*' : '4XX*'}</b>`);
        parts.push('Most common error: <b>Outcome-only snapshot</b> · <b>1</b>');
        parts.push('Example: Bridge snapshot provides aggregate outcomes only (no SMTP response text).');
        parts.push([
          `4XX temporary: <b>${estTemp}</b>`,
          `5XX blocked: <b>${estBlocked}</b>`
        ].join(' · '));
        el.innerHTML = parts.join('<br>');
      }else{
        el.textContent = '—';
      }
    }else{
      const parts = [];
      if(latestError){
        const latestCode = pickErrorCode(latestError.detail || '') || '—';
        parts.push(`Latest code: <b>${esc(latestCode)}</b>`);
      }
      if(topSig){
        const [sig, info] = topSig;
        parts.push(`Most common error: <b>${esc(sig)}</b> · <b>${Number(info.count||0)}</b>`);
        const sample = (info.sample && info.sample.detail) ? info.sample.detail : '';
        if(sample){
          parts.push(`Example: ${esc(sample)}`);
        }
      }
      if(entries.length){
        parts.push(entries.map(([k,v]) => `${esc(labels[k] || k)}: <b>${Number(v||0)}</b>`).join(' · '));
      }
      el.innerHTML = parts.join('<br>');
    }

    function shortWords(txt, maxWords){
      const words = (txt || '').toString().replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
      return words.slice(0, Math.max(1, Number(maxWords || 4))).join(' ');
    }

    function pickErrorCode(txt){
      const s = (txt || '').toString();
      let m = s.match(/\b([245]\.\d\.\d{1,3})\b/i);
      if(m) return (m[1] || '').trim();
      m = s.match(/\b([245]\d\d)\b/);
      if(m) return (m[1] || '').trim();
      return '';
    }

    function pickErrorSummary(x){
      if(!x) return '';
      const typ = (x.type || '').toString().trim().toLowerCase();
      const kind = (x.kind || '').toString().trim().toLowerCase();
      if(typ) return typ;
      if(kind === 'temporary_error') return 'deferred';
      if(kind === 'blocked') return 'blocked';
      if(kind === 'accepted') return 'accepted';
      return kind || 'unknown';
    }

    // Error 1 (summary): latest status keyword from PMTA (bounced/deferred/complained/blocked/backoff...)
    const el2 = qk(card,'lastErrors');
    const pmtaErrorSummaryEl = qk(card,'pmtaErrorSummary');
    let errorSummaryLine1 = '—';
    if(el2){
      if(!latestError){
        if(hasOutcomeFailures){
          if(bouncedN + complainedN > 0){
            errorSummaryLine1 = `• [5XX*] bounced/complained · count=${esc(String(bouncedN + complainedN))}`;
          }else{
            errorSummaryLine1 = `• [4XX*] deferred · count=${esc(String(deferredN))}`;
          }
        }else{
          errorSummaryLine1 = '—';
        }
      }
      else{
        const detail = (latestError.detail || '').toString();
        const code = pickErrorCode(detail) || ((latestError.kind === 'temporary_error') ? '4XX' : '5XX');
        const summary = pickErrorSummary(latestError) || shortWords(detail, 4) || 'unknown';
        errorSummaryLine1 = `• [${esc(code)}] ${esc(summary)}`;
      }
      el2.innerHTML = errorSummaryLine1;
    }

    // Error 2 (details): latest full PowerMTA response detail
    const el3 = qk(card,'lastErrors2');
    let errorSummaryLine2 = '';
    if(el3){
      if(!latestError){
        if(hasOutcomeFailures){
          const mode = ((j.bridge_mode || '').toString().toLowerCase() || 'counts');
          const src = (mode === 'legacy') ? 'event ingestion' : 'bridge snapshot';
          errorSummaryLine2 = `• aggregate outcomes present (bounced=${esc(String(bouncedN))} · deferred=${esc(String(deferredN))} · complained=${esc(String(complainedN))}) · source=${esc(src)} · no per-recipient SMTP detail in this mode`;
        }else{
          errorSummaryLine2 = '';
        }
      }
      else{
        const typ = (latestError.type || '').toString();
        const kind = (latestError.kind || '').toString();
        const code = pickErrorCode(latestError.detail || '');
        const codePart = code ? ` · code=${esc(code)}` : '';
        errorSummaryLine2 = `• ${esc(latestError.email || '—')} · type=${esc(typ || 'unknown')} · kind=${esc(kind || 'unknown')}${codePart} · ${esc(latestError.detail || '')}`;
      }
      el3.innerHTML = errorSummaryLine2 || '—';
    }

    if(pmtaErrorSummaryEl){
      const hasErrorSummary = (errorSummaryLine1 && errorSummaryLine1 !== '—') || !!errorSummaryLine2;
      pmtaErrorSummaryEl.innerHTML = hasErrorSummary
        ? [errorSummaryLine1 || '', errorSummaryLine2 || ''].filter(Boolean).join('<br>')
        : '';
      pmtaErrorSummaryEl.style.display = hasErrorSummary ? '' : 'none';
    }

    function isNetworkInternalError(x){
      if(!x) return false;
      const t = (x.type || '').toString().toLowerCase();
      const d = (x.detail || '').toString().toLowerCase();
      const bag = `${t} ${d}`;
      return (
        bag.includes('network') ||
        bag.includes('socket') ||
        bag.includes('timeout') ||
        bag.includes('timed out') ||
        bag.includes('connection refused') ||
        bag.includes('connection reset') ||
        bag.includes('name or service not known') ||
        bag.includes('temporary failure in name resolution') ||
        bag.includes('host unreachable') ||
        bag.includes('no route to host') ||
        bag.includes('broken pipe') ||
        bag.includes('ssl') ||
        bag.includes('tls')
      );
    }

    const allInternalRows = Array.isArray(j.internal_last_errors) ? j.internal_last_errors : [];
    const netInternalRows = allInternalRows.filter(isNetworkInternalError);
    const ieRows = netInternalRows.slice().reverse().slice(0,10);
    const ieAgg = {};
    for(const row of netInternalRows){
      const k = (row && row.type) ? row.type.toString() : 'network_error';
      ieAgg[k] = Number(ieAgg[k] || 0) + 1;
    }
    const ie = qk(card,'internalErrors');
    if(ie){
      const topFixed = Object.entries(ieAgg).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0));
      const countLine = topFixed.length
        ? topFixed.map(([k,v]) => `${esc(k)}: <b>${Number(v||0)}</b>`).join(' · ')
        : '';

      if(!countLine && !ieRows.length){
        ie.textContent = '—';
      }else{
        const lines = [];
        if(countLine) lines.push(countLine);
        if(ieRows.length){
          lines.push(ieRows.map(x => {
            const jid = (x.job_id || '').toString();
            const em = (x.email || '').toString();
            const ts = (x.ts || '').toString();
            const extra = [jid ? `job=${jid}` : '', em ? `email=${em}` : ''].filter(Boolean).join(' · ');
            return `• ${esc(ts)} · [${esc(x.type || 'other')}] ${esc(x.detail || '')}${extra ? ` · ${esc(extra)}` : ''}`;
          }).join('<br>'));
        }
        ie.innerHTML = lines.join('<br>');
      }
    }
  }



  function renderIssueBlocks(card, j){
    const asNum = (v) => {
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const fmtRate = (n, d) => {
      if(n === null || d === null || d <= 0) return '—';
      return `${((n/d)*100).toFixed(1)}%`;
    };

    const bridgeFail = asNum(j.bridge_failure_count);
    const bridgeErr = (j.bridge_last_error_message || '').toString().trim();
    const bridgeAge = ageMin(j.bridge_last_success_ts);
    const internalCounts = j.internal_error_counts || {};
    const runtimeErr = Object.values(internalCounts).reduce((a,v)=>a+Number(v||0),0);
    const dbFail = asNum(j.db_write_failures);

    const sys = qk(card,'systemSummary');
    if(sys){
      const bits = [
        `🔗 Bridge failures: <b>${bridgeFail === null ? '—' : bridgeFail}</b>`,
        `⏱️ Last bridge success: <b>${bridgeAge === null ? '—' : (bridgeAge + 'm ago')}</b>`,
        `⚙️ Runtime internal errors: <b>${runtimeErr || 0}</b>`,
        `💾 DB write failures: <b>${dbFail === null ? '—' : dbFail}</b>`,
      ];
      if(bridgeErr) bits.push(`🚨 Bridge last error: ${esc(bridgeErr.slice(0,140))}`);
      sys.innerHTML = bits.join(' · ');
    }

    const sysRows = [];
    const irows = Array.isArray(j.internal_last_samples) ? j.internal_last_samples : (Array.isArray(j.internal_last_errors) ? j.internal_last_errors : []);
    for(const x of irows.slice().reverse().slice(0,8)){
      sysRows.push(`• ${esc(x.ts || '—')} · [${esc(x.type || 'internal')}] ${esc((x.detail || '').toString().slice(0,180))}`);
    }
    const sysDet = qk(card,'systemDetails');
    if(sysDet) sysDet.innerHTML = sysRows.length ? sysRows.join('<br>') : '—';

    const sent = asNum(j.sent);
    const delivered = asNum(j.delivered);
    const deferred = asNum(j.deferred);
    const bounced = asNum(j.bounced);
    const complained = asNum(j.complained);

    const prov = qk(card,'providerSummary');
    if(prov){
      prov.innerHTML = [
        `✅ Delivered: <b>${delivered ?? '—'}</b> (${fmtRate(delivered, sent)})`,
        `⏳ Deferred: <b>${deferred ?? '—'}</b> (${fmtRate(deferred, sent)})`,
        `❌ Bounced: <b>${bounced ?? '—'}</b> (${fmtRate(bounced, sent)})`,
        `📢 Complained: <b>${complained ?? '—'}</b> (${fmtRate(complained, sent)})`,
      ].join(' · ');
    }

    const pb = qk(card,'providerBreakdown');
    const breakdown = Array.isArray(j.provider_breakdown) ? j.provider_breakdown : [];
    if(pb){
      pb.innerHTML = breakdown.length
        ? ('🌐 Provider/domain breakdown: ' + breakdown.slice(0,6).map(x => `${esc(x.domain || '—')} D=${Number(x.delivered||0)} Def=${Number(x.deferred||0)} B=${Number(x.bounced||0)} C=${Number(x.complained||0)}`).join(' · '))
        : '🌐 Provider/domain breakdown: —';
    }

    const pr = qk(card,'providerReasons');
    const reasons = j.provider_reason_buckets || {};
    const reasonEntries = Object.entries(reasons).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0)).slice(0,4);
    if(pr){
      pr.innerHTML = reasonEntries.length
        ? ('🧠 Top reason buckets: ' + reasonEntries.map(([k,v]) => `${esc(k)}=<b>${Number(v||0)}</b>`).join(' · '))
        : '🧠 Top reason buckets: —';
    }

    const provDet = qk(card,'providerDetails');
    if(provDet){
      const samples = (Array.isArray(j.accounting_last_errors) ? j.accounting_last_errors : []).filter(x => x && x.kind !== 'accepted').slice().reverse().slice(0,8);
      provDet.innerHTML = samples.length
        ? samples.map(x => `• ${esc(x.ts || '—')} · ${esc(x.email || '—')} · ${esc(x.type || '—')} · ${esc((x.detail || '').toString().slice(0,180))}`).join('<br>')
        : '—';
    }

    const dup = asNum(j.duplicates_dropped) || 0;
    const jnf = asNum(j.job_not_found) || 0;
    const miss = asNum(j.missing_fields) || 0;
    const dbwf = asNum(j.db_write_failures) || 0;
    const integ = qk(card,'integritySummary');
    if(integ){
      integ.innerHTML = `♻️ duplicates_dropped: <b>${dup}</b> · 🔎 job_not_found: <b>${jnf}</b> · 🧾 missing_fields: <b>${miss}</b> · 💽 db_write_failures: <b>${dbwf}</b>`;
    }

    const integDet = qk(card,'integrityDetails');
    const integRows = Array.isArray(j.integrity_last_samples) ? j.integrity_last_samples : [];
    if(integDet){
      integDet.innerHTML = integRows.length
        ? integRows.slice().reverse().slice(0,8).map(x => `• ${esc(x.ts || '—')} · ${esc(x.kind || 'integrity')} · job=${esc(x.job_id || '—')} · rcpt=${esc(x.rcpt || '—')}`).join('<br>')
        : '—';
    }
  }


  function renderChunkHist(card, j){
    const tb = qk(card,'chunkHist');
    if(!tb) return;
    const finalized = new Set(['done', 'done_after_backoff', 'abandoned']);
    const cs = (j.chunk_states || [])
      .filter(x => finalized.has((x?.status || '').toString().toLowerCase()))
      .slice()
      .reverse()
      .slice(0,12);
    if(!cs.length){
      tb.innerHTML = `<tr><td colspan="10" class="mini">No chunk states yet.</td></tr>`;
      return;
    }
    tb.innerHTML = cs.map(x => {
      const next = x.next_retry_ts ? new Date(Number(x.next_retry_ts)*1000).toLocaleTimeString() : '';
      const bl = (x.blacklist || '').toString();
      const blShort = bl.length > 30 ? (bl.slice(0,30) + '…') : bl;
      const sender = (x.sender || '').toString();
      const senderShort = sender.length > 30 ? (sender.slice(0,30) + '…') : sender;
      const receiverDomain = (x.target_domain || x.provider_domain || '').toString();
      const spam = (x.spam_score === null || x.spam_score === undefined) ? '' : Number(x.spam_score).toFixed(2);
      const reason = (x.reason || '').toString();
      const reasonShort = reason.length > 40 ? (reason.slice(0,40) + '…') : reason;
      const attempt = (x.attempt === null || x.attempt === undefined || x.attempt === '') ? '—' : String(x.attempt);
      const retryText = next || '—';

      return `<tr>`+
        `<td>${Number(x.chunk)+1}</td>`+
        `<td>${esc(x.status || '')}</td>`+
        `<td>${Number(x.size||0)}</td>`+
        `<td title="${esc(sender)}">${esc(senderShort)}</td>`+
        `<td>${esc(receiverDomain)}</td>`+
        `<td>${esc(spam)}</td>`+
        `<td title="${esc(bl)}">${esc(blShort)}</td>`+
        `<td><b>${esc(attempt)}</b></td>`+
        `<td><span title="${esc(next || '')}">${esc(retryText)}</span></td>`+
        `<td title="${esc(reason)}">${esc(reasonShort || '—')}</td>`+
      `</tr>`;
    }).join('');
  }

  function renderChunkLive(card, j){
    const tb = qk(card,'chunkLive');
    if(!tb) return;
    const active = getLiveChunks(j);
    if(!active.length){
      const isRunning = ['running','backoff'].includes((j.status || '').toString().toLowerCase());
      const snap = (j.debug_parallel_lanes_snapshot && typeof j.debug_parallel_lanes_snapshot === 'object') ? j.debug_parallel_lanes_snapshot : {};
      const laneCount = Number(snap.lanes_active ?? snap.active_lanes ?? snap.lanes ?? 0);
      const v2Active = !!j.v2_parallel_enabled || laneCount > 0;
      if(isRunning && v2Active){
        tb.innerHTML = `<tr><td colspan="7" class="mini">⚠️ No live chunk rows yet from active_chunks_info. This can be a brief telemetry gap in V2 parallel mode (lanes=${Number.isFinite(laneCount) ? laneCount : 0}).</td></tr>`;
      }else{
        tb.innerHTML = `<tr><td colspan="7" class="mini">No active chunk right now.</td></tr>`;
      }
      return;
    }
    tb.innerHTML = active.slice(0,12).map(ci => {
      const sender = (ci.sender_mail || ci.sender || '').toString();
      const senderShort = sender.length > 30 ? (sender.slice(0,30) + '…') : sender;
      const receiverDomain = (ci.receiver_domain || ci.target_domain || '').toString();
      const spam = (ci.spam_score === null || ci.spam_score === undefined) ? '—' : Number(ci.spam_score).toFixed(2);
      const bl = (ci.blacklist || '').toString();
      const blShort = bl.length > 30 ? (bl.slice(0,30) + '…') : bl;
      const status = (ci.status || (((j.status || '').toString().toLowerCase() === 'backoff') ? 'backoff' : 'running'));
      const laneBadge = (ci.lane_id !== undefined && ci.lane_id !== null && ci.lane_id !== '')
        ? ` · lane ${esc(String(ci.lane_id))}`
        : '';
      return `<tr>`+
        `<td>${Number(ci.chunk_id ?? ci.chunk)+1}${laneBadge}</td>`+
        `<td>${esc(status)}</td>`+
        `<td>${Number(ci.size||0)}</td>`+
        `<td title="${esc(sender)}">${esc(senderShort || '—')}</td>`+
        `<td>${esc(receiverDomain || '—')}</td>`+
        `<td>${esc(spam)}</td>`+
        `<td title="${esc(bl)}">${esc(blShort || '—')}</td>`+
      `</tr>`;
    }).join('');
  }

  function normalizeLiveChunkStatus(rawStatus, jobStatus){
    const s = (rawStatus || '').toString().toLowerCase();
    if(s === 'backoff') return 'backoff';
    if(s === 'running') return 'running';
    const js = (jobStatus || '').toString().toLowerCase();
    return js === 'backoff' ? 'backoff' : 'running';
  }

  function isV2ChunkTelemetry(j){
    const source = (j?.telemetry_source || '').toString().toLowerCase();
    if(source === 'v2') return true;
    const runtimeMode = (j?.debug_parallel_lanes_snapshot?.mode || '').toString().toLowerCase();
    return runtimeMode === 'v2' || !!j?.v2_parallel_enabled;
  }

  function hasLiveIdentity(ci){
    if(!ci || typeof ci !== 'object') return false;
    const hasChunk = ci.chunk_id !== undefined && ci.chunk_id !== null && ci.chunk_id !== '';
    const hasChunkAlt = ci.chunk !== undefined && ci.chunk !== null && ci.chunk !== '';
    const hasLane = ci.lane_id !== undefined && ci.lane_id !== null && ci.lane_id !== '';
    const hasLaneAlt = ci.lane !== undefined && ci.lane !== null && ci.lane !== '';
    const hasDomain = !!((ci.target_domain || ci.receiver_domain || '').toString().trim());
    return hasChunk || hasChunkAlt || hasLane || hasLaneAlt || hasDomain;
  }

  function liveChunkSort(a, b){
    const rank = (x) => (normalizeLiveChunkStatus(x?.status, '').toLowerCase() === 'running' ? 0 : 1);
    const byStatus = rank(a) - rank(b);
    if(byStatus !== 0) return byStatus;
    const laneA = Number(a?.lane_id ?? a?.lane ?? Number.MAX_SAFE_INTEGER);
    const laneB = Number(b?.lane_id ?? b?.lane ?? Number.MAX_SAFE_INTEGER);
    if(laneA !== laneB) return laneA - laneB;
    const chunkA = Number(a?.chunk_id ?? a?.chunk ?? Number.MAX_SAFE_INTEGER);
    const chunkB = Number(b?.chunk_id ?? b?.chunk ?? Number.MAX_SAFE_INTEGER);
    return chunkA - chunkB;
  }

  function getLiveChunks(j){
    const isV2 = isV2ChunkTelemetry(j);
    const active = Array.isArray(j.active_chunks_info)
      ? j.active_chunks_info
          .filter(x => hasLiveIdentity(x))
          .map(x => ({
            ...x,
            status: normalizeLiveChunkStatus(x?.status, j?.status),
            lane_id: x?.lane_id ?? x?.lane,
          }))
          .sort(liveChunkSort)
      : [];
    if(active.length) return active;

    const running = Array.isArray(j.chunk_states)
      ? j.chunk_states
          .filter(x => ['running', 'backoff'].includes((x?.status || '').toString().toLowerCase()))
          .slice(-12)
          .map(x => ({
            chunk_id: x.chunk,
            status: x.status,
            size: x.size,
            sender_mail: x.sender,
            receiver_domain: x.target_domain || x.provider_domain || '',
            spam_score: x.spam_score,
            blacklist: x.blacklist,
            lane_id: x.lane_id ?? x.lane,
            target_domain: x.target_domain || x.provider_domain || '',
          }))
          .filter(x => hasLiveIdentity(x))
          .map(x => ({ ...x, status: normalizeLiveChunkStatus(x?.status, j?.status) }))
          .sort(liveChunkSort)
      : [];
    if(running.length) return running;

    const ci = j.current_chunk_info || {};
    const ciStatus = (ci?.status || '').toString().toLowerCase();
    const hasChunkId = ci.chunk_id !== undefined && ci.chunk_id !== null && ci.chunk_id !== '';
    const hasChunkAlt = ci.chunk !== undefined && ci.chunk !== null && ci.chunk !== '';
    const hasLane = !!((ci?.lane_id ?? ci?.lane ?? '').toString());
    const canUseCurrentAsLive = isV2
      ? ((hasChunkId || hasChunkAlt) && hasLane && ['running','backoff'].includes(ciStatus))
      : hasLiveIdentity(ci);
    return canUseCurrentAsLive
      ? [{ ...ci, status: normalizeLiveChunkStatus(ci?.status, j?.status), lane_id: ci?.lane_id ?? ci?.lane }]
      : [];
  }

  function updateCard(card, j){
    const jobId = card.dataset.jobid;

    // Header pills
    const st = (j.status || '').toString();
    const stEl = qk(card,'status');
    if(stEl){
      stEl.className = statusPillClass(st);
      stEl.textContent = `Status: ${st}`;
    }

    const speedEl = qk(card,'speed');
    const spm = Number(j.speed_epm || 0);
    if(speedEl){
      speedEl.className = 'pill';
      speedEl.textContent = `${Math.round(spm)} epm`;
    }

    const etaEl = qk(card,'eta');
    if(etaEl){
      etaEl.className = 'pill';
      etaEl.textContent = fmtEta(j.eta_s);
    }

    renderTriageBadges(card, j);

    // Core counters + compact KPI values
    const asNum = (v) => {
      if(v === null || v === undefined || v === '') return null;
      const n = Number(v);
      return Number.isFinite(n) ? n : null;
    };
    const fmtNum = (n) => (n === null ? '—' : String(n));
    const fmtRate = (num, den) => {
      if(num === null || den === null || den <= 0) return '—';
      const r = (num / den) * 100;
      return `${r.toFixed(2)}%`;
    };

    const totalN = asNum(j.total);
    const sentN = asNum(j.sent);
    const failedN = asNum(j.failed);
    const skippedN = asNum(j.skipped);
    const invalidN = asNum(j.invalid);
    const deliveredN = asNum(j.delivered);
    const bouncedN = asNum(j.bounced);
    const deferredN = asNum(j.deferred);
    const complainedN = asNum(j.complained);

    qk(card,'total').textContent = fmtNum(totalN);
    qk(card,'sent').textContent = fmtNum(sentN);
    qk(card,'failed').textContent = fmtNum(failedN);
    qk(card,'skipped').textContent = fmtNum(skippedN);
    qk(card,'invalid').textContent = fmtNum(invalidN);

    const elDel = qk(card,'delivered'); if(elDel) elDel.textContent = fmtNum(deliveredN);
    const elBnc = qk(card,'bounced'); if(elBnc) elBnc.textContent = fmtNum(bouncedN);
    const elDef = qk(card,'deferred'); if(elDef) elDef.textContent = fmtNum(deferredN);
    const elCmp = qk(card,'complained'); if(elCmp) elCmp.textContent = fmtNum(complainedN);

    let pendingValue = null;
    let pendingClamped = false;
    if(sentN !== null && deliveredN !== null && bouncedN !== null && deferredN !== null && complainedN !== null){
      pendingValue = sentN - (deliveredN + bouncedN + deferredN + complainedN);
      if(pendingValue < 0){
        pendingValue = 0;
        pendingClamped = true;
      }
    }
    qk(card,'pending').textContent = fmtNum(pendingValue);
    const pendingWarnEl = qk(card,'pendingWarn');
    if(pendingWarnEl) pendingWarnEl.style.display = pendingClamped ? '' : 'none';

    const rateBounceEl = qk(card,'rateBounce');
    const rateComplaintEl = qk(card,'rateComplaint');
    const rateDeferredEl = qk(card,'rateDeferred');
    if(rateBounceEl) rateBounceEl.textContent = fmtRate(bouncedN, sentN);
    if(rateComplaintEl) rateComplaintEl.textContent = fmtRate(complainedN, sentN);
    if(rateDeferredEl) rateDeferredEl.textContent = fmtRate(deferredN, sentN);

    // Progress bars
    const total = Number(j.total||0);
    const sent = Number(j.sent||0);
    const failed = Number(j.failed||0);
    const skipped = Number(j.skipped||0);
    const done = sent + failed + skipped;

    const pSend = pct(done, total);
    qk(card,'barSend').style.width = pSend + '%';
    qk(card,'progressText').textContent = `Send progress: ${pSend}% (${done}/${total})`; 

    const legacyDone = Number(j.chunks_done||0);
    const legacyTotal = Number(j.chunks_total||0);
    let chunkUniqueDone = Number(j.chunk_unique_done);
    if(!Number.isFinite(chunkUniqueDone)) chunkUniqueDone = legacyDone;
    if(!Number.isFinite(chunkUniqueDone) || chunkUniqueDone < 0) chunkUniqueDone = 0;

    let chunkUniqueTotal = Number(j.chunk_unique_total);
    if(!Number.isFinite(chunkUniqueTotal)) chunkUniqueTotal = legacyTotal;
    if(!Number.isFinite(chunkUniqueTotal) || chunkUniqueTotal < 0) chunkUniqueTotal = 0;
    if(chunkUniqueTotal < chunkUniqueDone) chunkUniqueTotal = chunkUniqueDone;

    const pChunks = pct(chunkUniqueDone, chunkUniqueTotal);
    qk(card,'barChunks').style.width = pChunks + '%';
    qk(card,'chunksText').textContent = `Chunks: ${chunkUniqueDone}/${chunkUniqueTotal} done · backoff_events=${Number(j.chunks_backoff||0)} · abandoned=${Number(j.chunks_abandoned||0)}`;
    const attemptsEl = qk(card,'attemptsText');
    if(attemptsEl){
      let attemptsTotal = Number(j.chunk_attempts_total);
      if(!Number.isFinite(attemptsTotal)) attemptsTotal = null;
      if(attemptsTotal !== null && attemptsTotal < 0) attemptsTotal = null;
      if(attemptsTotal !== null && attemptsTotal < chunkUniqueDone) attemptsTotal = chunkUniqueDone;
      const hasRetries = attemptsTotal !== null && attemptsTotal > chunkUniqueDone;
      if(hasRetries){
        attemptsEl.style.display = '';
        attemptsEl.textContent = `Attempts: ${attemptsTotal}`;
      }else{
        attemptsEl.style.display = 'none';
      }
    }

    const plan = j.domain_plan || {};
    const planTotal = Object.values(plan).reduce((a,v)=>a+Number(v||0),0);
    const dSent = j.domain_sent || {};
    const dFail = j.domain_failed || {};
    const domDone = Object.keys(plan).reduce((a,dom)=>a+Number(dSent[dom]||0)+Number(dFail[dom]||0),0);
    const pDom = pct(domDone, planTotal);
    qk(card,'barDomains').style.width = pDom + '%';
    qk(card,'domainsText').textContent = `Domains: ${pDom}% (${domDone}/${planTotal})`; 

    // Current chunk info (parallel-aware)
    const liveChunks = getLiveChunks(j);
    const ci = liveChunks[0] || (j.current_chunk_info || {});
    const cDom = j.current_chunk_domains || {};
    const activeDomainsMap = {};
    for(const row of liveChunks){
      const d = ((row?.target_domain || row?.receiver_domain || '') + '').trim().toLowerCase();
      if(!d) continue;
      activeDomainsMap[d] = Number(activeDomainsMap[d] || 0) + 1;
    }

    let chunkLine = '<div class="mini">—</div>';
    if(ci && ((ci.chunk !== undefined && ci.chunk !== null) || (ci.chunk_id !== undefined && ci.chunk_id !== null)) && Number(ci.size||0) > 0){
      const cnum = Number((ci.chunk_id ?? ci.chunk) || 0) + 1;
      const at = Number(ci.attempt||0);
      const sender = (ci.sender || ci.sender_mail || '').toString();
      const subj = (ci.subject||'').toString();
      const subjShort = subj.length > 70 ? (subj.slice(0,70) + '…') : subj;
      const spam = (ci.spam_score === null || ci.spam_score === undefined) ? '—' : Number(ci.spam_score).toFixed(2);
      const bl = (ci.blacklist || '').toString();
      const blShort = bl.length > 60 ? (bl.slice(0,60) + '…') : bl;
      const pmtaReason = (ci.pmta_reason || '').toString();
      const pmtaReasonShort = pmtaReason.length > 80 ? (pmtaReason.slice(0,80) + '…') : pmtaReason;
      let pmtaSlowShort = '';
      let adaptiveShort = '';
      try{
        const ps = ci.pmta_slow || {};
        const dmin = (ps.delay_min !== undefined && ps.delay_min !== null) ? Number(ps.delay_min) : null;
        const wmax = (ps.workers_max !== undefined && ps.workers_max !== null) ? Number(ps.workers_max) : null;
        if((dmin !== null && !Number.isNaN(dmin)) || (wmax !== null && !Number.isNaN(wmax))){
          const parts = [];
          if(dmin !== null && !Number.isNaN(dmin)) parts.push('delay≥' + dmin);
          if(wmax !== null && !Number.isNaN(wmax)) parts.push('workers≤' + wmax);
          pmtaSlowShort = parts.join(', ');
        }
      }catch(e){ /* ignore */ }

      try{
        const ah = ci.adaptive_health || {};
        if(ah && ah.ok){
          const lvl = Number(ah.level || 0);
          const reduced = !!ah.reduced;
          const action = (ah.action || '').toString();
          const ap = ah.applied || {};
          const bits = [];
          if(ap.workers !== undefined) bits.push(`w=${Number(ap.workers)}`);
          if(ap.chunk_size !== undefined) bits.push(`chunk=${Number(ap.chunk_size)}`);
          if(ap.delay_s !== undefined) bits.push(`delay=${Number(ap.delay_s)}s`);
          adaptiveShort = `health[L${lvl}${reduced ? '↓' : ''}${action ? (':' + action) : ''}${bits.length ? (' ' + bits.join(',')) : ''}]`;
        }
      }catch(e){ /* ignore */ }

      const spamN = Number(ci.spam_score);
      const spamTone = Number.isFinite(spamN) ? (spamN >= 4 ? 'bad' : (spamN >= 2 ? 'warn' : 'good')) : '';
      const hasBl = !!(blShort && blShort.trim());
      const blTone = hasBl ? 'warn' : 'good';

      const cdEntriesInlineSource = Object.keys(activeDomainsMap).length ? activeDomainsMap : cDom;
      const cdEntriesInline = Object.entries(cdEntriesInlineSource).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0)).slice(0,6);
      const activeDomainsTxt = cdEntriesInline.length
        ? cdEntriesInline.map(([d,c]) => `${esc(d)}(${Number(c||0)})`).join(' · ')
        : '—';

      chunkLine = [
        (liveChunks.length > 1)
          ? `<div class="mini" style="margin-bottom:6px"><b>Live chunks:</b> ${Number(liveChunks.length)} parallel lanes active.</div>`
          : '',
        `<div class="chunkMeta">`,
          `<span class="chunkMetaPill">#️⃣ Chunk #${cnum}</span>`,
          `<span class="chunkMetaPill">📦 size=${Number(ci.size||0)}</span>`,
          `<span class="chunkMetaPill">⚙️ workers=${Number(ci.workers||0)}</span>`,
          `<span class="chunkMetaPill">⏱️ delay=${Number(ci.delay_s||0)}s</span>`,
          `<span class="chunkMetaPill">🔁 attempt=${at}</span>`,
        `</div>`,
        `<div class="chunkList">`,
          `<div class="chunkItem"><span class="chunkIcon">📧</span><div><div class="chunkLabel">Sender</div><div class="chunkValue">${esc(sender || '—')}</div></div></div>`,
          `<div class="chunkItem"><span class="chunkIcon">🧪</span><div><div class="chunkLabel">Spam / BL</div><div class="chunkValue ${spamTone}">Spam: ${esc(spam)}</div><div class="chunkValue ${blTone}">BL: ${esc(blShort || '—')}</div></div></div>`,
          `<div class="chunkItem"><span class="chunkIcon">📝</span><div><div class="chunkLabel">Subject</div><div class="chunkValue">${esc(subjShort || '—')}</div></div></div>`,
          `<div class="chunkItem"><span class="chunkIcon">🌐</span><div><div class="chunkLabel">Active domains</div><div class="chunkValue">${activeDomainsTxt}</div></div></div>`,
        `</div>`,
      ].join('') +
      (pmtaReasonShort ? (`<div class="mini chunkNote">🛰️ PMTA reason: ${esc(pmtaReasonShort)}</div>`) : '')+
      (pmtaSlowShort ? (`<div class="mini chunkNote">🐢 PMTA slow: ${esc(pmtaSlowShort)}</div>`) : '')+
      (adaptiveShort ? (`<div class="mini chunkNote chunkNoteAdaptive">🧠 Adaptive: ${esc(adaptiveShort)}</div>`) : '');
    }
    qk(card,'chunkLine').innerHTML = chunkLine;

    // active domains for current chunk
    const cdEntriesSource = Object.keys(activeDomainsMap).length ? activeDomainsMap : cDom;
    const cdEntries = Object.entries(cdEntriesSource).sort((a,b)=>Number(b[1]||0)-Number(a[1]||0)).slice(0,6);
    qk(card,'chunkDomains').innerHTML = cdEntries.length
      ? ('<div class="mini chunkNote chunkNoteDomains">🔥 Top active domains: ' + cdEntries.map(([d,c]) => `${esc(d)}(${Number(c||0)})`).join(' · ') + '</div>')
      : '<div class="mini chunkNote chunkNoteDomains">🔥 Top active domains: —</div>';

    // Backoff info (parallel-aware)
    const liveBackoffs = liveChunks
      .filter(x => normalizeLiveChunkStatus(x?.status, st) === 'backoff')
      .slice(0,5);
    const cs = (j.chunk_states || []).slice().reverse();
    let backLine = '—';
    if(liveBackoffs.length){
      const parts = liveBackoffs.map(x => {
        const next = x.next_retry_ts ? new Date(Number(x.next_retry_ts)*1000).toLocaleTimeString() : '—';
        const dom = (x.target_domain || x.receiver_domain || '').toString();
        const reason = (x.reason || '').toString();
        const reasonShort = reason.length > 64 ? (reason.slice(0,64) + '…') : reason;
        const label = `#${Number((x.chunk_id ?? x.chunk) || 0) + 1}`;
        const meta = `${dom ? (dom + ' · ') : ''}retry=${Number(x.attempt||0)} · next=${next}`;
        return `${label} (${meta}${reasonShort ? (' · ' + reasonShort) : ''})`;
      });
      const suffix = (liveBackoffs.length < (liveChunks.filter(x => normalizeLiveChunkStatus(x?.status, st) === 'backoff').length || 0)) ? ' …' : '';
      backLine = `Active backoff lanes: ${parts.join(' | ')}${suffix}`;
    }else{
      const lastBack = cs.find(x => (x.status || '') === 'backoff');
      if(lastBack){
        const next = lastBack.next_retry_ts ? new Date(Number(lastBack.next_retry_ts)*1000).toLocaleTimeString() : '';
        const rs = (lastBack.reason || '').toString();
        const rshort = rs.length > 120 ? (rs.slice(0,120) + '…') : rs;
        backLine = `Latest backoff: chunk #${Number(lastBack.chunk||0)+1} retry=${Number(lastBack.attempt||0)} · next=${next || '—'} · ${rshort}`;
      } else if((st||'').toLowerCase() === 'backoff'){
        backLine = 'Backoff active across one or more lanes (waiting for retry telemetry)…';
      }
    }
    qk(card,'backoffLine').textContent = backLine;
    // PMTA Live Panel (optional) — richer UI
    const pmEl = qk(card,'pmtaLine');
    const pmCompactEl = qk(card,'pmtaCompact');
    const pmDiagEl = qk(card,'pmtaDiag');
    const pmNoteEl = qk(card,'pmtaNote');
    if(pmNoteEl){
      pmNoteEl.innerHTML = 'Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.';
    }

    function _pmFmt(v){ return (v === null || v === undefined) ? '—' : v; }
    function _pmNum(v){
      const n = Number(v);
      return (Number.isFinite(n) ? n : null);
    }

    function _pmTone(kind, n){
      // kind: 'backlog'|'deferred'|'conns'|'pressure'
      if(n === null) return '';
      const x = Number(n);
      if(kind === 'deferred'){
        if(x >= 100) return 'bad';
        if(x > 0) return 'warn';
        return 'good';
      }
      if(kind === 'backlog'){
        // backlog usually means spool/queue accumulating
        if(x >= 50000) return 'bad';
        if(x > 0) return 'warn';
        return 'good';
      }
      if(kind === 'pressure'){
        if(x >= 3) return 'bad';
        if(x >= 1) return 'warn';
        return 'good';
      }
      // conns
      if(x >= 800) return 'warn';
      return 'good';
    }

    function _pmTrafficTone(inCount, outCount){
      const inN = _pmNum(inCount);
      const outN = _pmNum(outCount);
      if(inN === null || outN === null) return '';
      if(inN <= 0){
        if(outN <= 0) return 'warn';
        return 'good';
      }
      const ratio = outN / inN;
      if(ratio < 0.25) return 'bad';
      if(ratio <= 0.5) return 'warn';
      return 'good';
    }

    function _tagHtml(tone, label){
      const cls = tone ? ('tag ' + tone) : 'tag';
      return `<span class="${cls}">${esc(label)}</span>`;
    }

    function _box(title, tagTone, tagLabel, hint, inner){
      return `<div class="pmtaBox">`+
        `<div class="pmtaTitle"><span>${esc(title)}</span>${tagLabel ? _tagHtml(tagTone, tagLabel) : ''}</div>`+
        (hint ? `<div class="pmtaHint">${esc(hint)}</div>` : '')+
        (inner || '')+
      `</div>`;
    }

    function _kv(k, v, tone, big){
      const cls = 'pmtaVal' + (tone ? (' ' + tone) : '') + (big ? ' pmtaBig' : '');
      return `<div class="pmtaRow"><span class="pmtaKey">${esc(k)}</span><span class="${cls}">${esc(String(v))}</span></div>`;
    }

    function _renderPmtaPanel(pm, pr){
      if(!pm || !pm.enabled){
        const why = (pm && pm.reason) ? String(pm.reason) : '';
        return `<div class="pmtaBanner warn">PMTA: disabled${why ? (`<br><span class="muted">${esc(why)}</span>`) : ''}</div>`;
      }
      if(!pm.ok){
        const why = (pm.reason || 'unreachable').toString();
        return `<div class="pmtaBanner bad">PMTA monitor unreachable<br><span class="muted">${esc(why)}</span></div>`;
      }

      const spR = _pmFmt(pm.spool_recipients);
      const spM = _pmFmt(pm.spool_messages);
      const qR  = _pmFmt(pm.queued_recipients);
      const qM  = _pmFmt(pm.queued_messages);
      const con = _pmFmt(pm.active_connections);
      const conIn = _pmFmt(pm.smtp_in_connections);
      const conOut = _pmFmt(pm.smtp_out_connections);
      const hrIn = _pmFmt(pm.traffic_last_hr_in);
      const hrOut = _pmFmt(pm.traffic_last_hr_out);
      const minIn = _pmFmt(pm.traffic_last_min_in);
      const minOut = _pmFmt(pm.traffic_last_min_out);
      const ts  = pm.ts ? String(pm.ts) : '';

      const spR_n = _pmNum(pm.spool_recipients);
      const qR_n  = _pmNum(pm.queued_recipients);
      const con_n = _pmNum(pm.active_connections);
      const hrIn_n = _pmNum(pm.traffic_last_hr_in);
      const hrOut_n = _pmNum(pm.traffic_last_hr_out);
      const minIn_n = _pmNum(pm.traffic_last_min_in);
      const minOut_n = _pmNum(pm.traffic_last_min_out);

      const toneSp = _pmTone('backlog', spR_n);
      const toneQ  = _pmTone('backlog', qR_n);
      const toneHr = _pmTrafficTone(hrIn_n, hrOut_n);
      const toneMin = _pmTrafficTone(minIn_n, minOut_n);
      const toneC  = _pmTone('conns', con_n);

      // top queues
      let topTxt = '—';
      try{
        const tqs = Array.isArray(pm.top_queues) ? pm.top_queues : [];
        if(tqs.length){
          const top = tqs.slice(0, 4).map(x => {
            const qn = (x.queue ?? '').toString();
            const dm = (x.domain ?? '').toString();
            const rr = (x.recipients ?? 0);
            const dd = (x.deferred ?? 0);
            const le = (x.last_error ?? '').toString();
            const base = `${qn}=${rr}` + (dd ? (`(def:${dd})`) : '');
            const domPart = dm ? (` [${dm}]`) : '';
            const errPart = le ? (` · err: ${le.slice(0,70)}`) : '';
            return base + domPart + errPart;
          });
          topTxt = top.join(' · ');
        }
      }catch(e){ topTxt = '—'; }

      const html = `
        <div class="pmtaGrid">
          ${_box('Spool', toneSp, 'rcpt', 'Total recipients/messages currently held by PMTA spool.', _kv('RCPT', spR, toneSp, true) + _kv('MSG', spM, toneSp, false))}
          ${_box('Queue', toneQ, 'rcpt', 'Recipients/messages still queued to be delivered.', _kv('RCPT', qR, toneQ, true) + _kv('MSG', qM, toneQ, false))}
          ${_box('Connections', toneC, '', 'Live SMTP sessions used for inbound/outbound traffic.', _kv('SMTP In', conIn, toneC, true) + _kv('SMTP Out', conOut, toneC, true) + _kv('Total', con, toneC, false))}
          ${_box('Last minute', toneMin, '', 'Recent PMTA throughput over the last 60 seconds.', _kv('In', minIn, toneMin, true) + _kv('Out', minOut, toneMin, true) + `<div class="pmtaSub">traffic recipients / minute</div>`)}
          ${_box('Last hour', toneHr, '', 'Rolling traffic totals for the previous 60 minutes.', _kv('In', hrIn, toneHr, true) + _kv('Out', hrOut, toneHr, true) + `<div class="pmtaSub">traffic recipients / hour</div>`)}
          ${_box('Top queues', (topTxt === '—' ? 'good' : 'warn'), '', 'Queues with the highest recipient backlog and latest queue errors.', `<div class="pmtaSub">${esc(topTxt)}</div>`)}
          ${_box('Time', 'good', '', 'Timestamp of the latest PMTA snapshot used for this panel.', `<div class="pmtaSub">${esc(ts || '—')}</div>`)}
        </div>
      `;
      return html;
    }

    function _renderPmtaCompact(pm){
      if(!pm || !pm.enabled || !pm.ok) return 'PMTA: —';
      const queue = _pmNum(pm.queued_recipients);
      const minOut = _pmNum(pm.traffic_last_min_out);
      const hrOut = _pmNum(pm.traffic_last_hr_out);
      if(queue === null && minOut === null && hrOut === null) return 'PMTA: —';
      return `Queue: ${_pmFmt(queue)} | last min out: ${_pmFmt(minOut)} | last hour out: ${_pmFmt(hrOut)}`;
    }

    if(pmEl){
      const pm = j.pmta_live || null;
      const pr = j.pmta_pressure || null;
      pmEl.innerHTML = _renderPmtaPanel(pm, pr);
    }
    if(pmCompactEl){
      const pm = j.pmta_live || null;
      pmCompactEl.textContent = _renderPmtaCompact(pm);
    }

    // PMTA diagnostics snapshot (point 7)

    if(pmDiagEl){
      const d = j.pmta_diag || {};
      if(d && d.enabled && d.ok){
        const cls = (d.class || '');
        const dom = (d.domain || '');
        const def = (d.queue_deferrals ?? '—');
        const err = (d.queue_errors ?? '—');
        const hint = (d.remote_hint || '');
        const samp = Array.isArray(d.errors_sample) ? d.errors_sample.slice(0,2).join(' / ') : '';
        pmDiagEl.innerHTML = [
          `<span class="chunkMetaPill">Diag</span>`,
          `<span class="chunkMetaPill">class=${esc(cls || '—')}</span>`,
          `<span class="chunkMetaPill">dom=${esc(dom || '—')}</span>`,
          `<span class="chunkMetaPill">def=${esc(String(def))}</span>`,
          `<span class="chunkMetaPill">err=${esc(String(err))}</span>`,
          hint ? `<span class="chunkMetaPill">hint=${esc(hint)}</span>` : '',
          samp ? `<span class="chunkMetaPill">sample=${esc(samp)}</span>` : ''
        ].join('');
      } else if(d && d.enabled && !d.ok) {
        pmDiagEl.innerHTML = `<span class="chunkMetaPill">Diag: ${esc(String(d.reason || '—'))}</span>`;
      } else {
        pmDiagEl.innerHTML = '<span class="chunkMetaPill">Diag: —</span>';
      }
    }

    // 6) Counters
    const counters = [
      `safe_total=${Number(j.safe_list_total||0)}`,
      `safe_invalid=${Number(j.safe_list_invalid||0)}`,
      `invalid_filtered=${Number(j.invalid||0)}`,
      `skipped=${Number(j.skipped||0)}`,
      `backoff_events=${Number(j.chunks_backoff||0)}`,
      `abandoned_chunks=${Number(j.chunks_abandoned||0)}`,
      `paused=${j.paused ? 'yes' : 'no'}`,
      `stop_requested=${j.stop_requested ? 'yes' : 'no'}`
    ];
    qk(card,'counters').textContent = counters.join(' · ');

    // Outcomes panel + trend (last ~20 minutes)
    const outEl = qk(card,'outcomes');
    const trEl = qk(card,'outcomeTrend');
    if(outEl){
      const ts = (j.accounting_last_ts || '').toString();
      const deliveredN = Number(j.delivered||0);
      const bouncedN = Number(j.bounced||0);
      const deferredN = Number(j.deferred||0);
      const complainedN = Number(j.complained||0);
      const sentN = Number(j.sent||0);
      const pendingByOutcome = Math.max(0, sentN - deliveredN - bouncedN - complainedN);
      const queuedNow = Number((((j.pmta_live || {}).queued_recipients) ?? 0) || 0);
      outEl.innerHTML = `
        <div class="outcomesGrid">
          <div class="outChip del"><span class="k">Delivered</span><span class="v">${deliveredN}</span></div>
          <div class="outChip bnc"><span class="k">Bounced</span><span class="v">${bouncedN}</span></div>
          <div class="outChip def"><span class="k">Deferred</span><span class="v">${deferredN}</span></div>
          <div class="outChip cmp"><span class="k">Complained</span><span class="v">${complainedN}</span></div>
        </div>
        <div class="outMeta">Pending (sent - final outcomes): <b>${pendingByOutcome}</b> · PMTA queue now: <b>${queuedNow}</b></div>
        <div class="outMeta">${ts ? (`Last accounting update: ${esc(ts)}`) : 'Last accounting update: —'}</div>
      `;
    }
    function spark(vals){
      const chars = '▁▂▃▄▅▆▇█';
      const mx = Math.max(1, ...vals.map(v=>Number(v||0)));
      return vals.map(v => {
        const x = Number(v||0);
        const idx = Math.max(0, Math.min(chars.length-1, Math.round((x/mx)*(chars.length-1))));
        return chars[idx];
      }).join('');
    }
    if(trEl){
      const s = Array.isArray(j.outcome_series) ? j.outcome_series : [];
      const tail = s.slice(-20);
      const delV = tail.map(x=>Number(x.delivered||0));
      const bncV = tail.map(x=>Number(x.bounced||0));
      const defV = tail.map(x=>Number(x.deferred||0));
      const cmpV = tail.map(x=>Number(x.complained||0));
      if(tail.length){
        trEl.innerHTML = [
          `<span class="trendHead">Trend</span>`,
          `<span class="trendSeg del"><span class="lbl">DEL</span><span class="spark">${esc(spark(delV))}</span></span>`,
          `<span class="trendSeg bnc"><span class="lbl">BNC</span><span class="spark">${esc(spark(bncV))}</span></span>`,
          `<span class="trendSeg def"><span class="lbl">DEF</span><span class="spark">${esc(spark(defV))}</span></span>`,
          `<span class="trendSeg cmp"><span class="lbl">CMP</span><span class="spark">${esc(spark(cmpV))}</span></span>`
        ].join(' ');
      } else {
        trEl.textContent = 'Trend · —';
      }
    }

    // 5) Top domains
    renderTopDomains(card, j);

    // 7) Error types + last errors (legacy section)
    renderErrorTypes(card, j);

    // Structured issue blocks
    renderIssueBlocks(card, j);

    // 8) Chunk history
    renderChunkLive(card, j);
    renderChunkHist(card, j);

    // 10) Alerts (simple)
    const alertsEl = qk(card,'alerts');
    const failRatio = (done > 0) ? (failed / done) : 0;
    const nearSpam = cs.find(x => (x.spam_score !== null && x.spam_score !== undefined && Number(x.spam_score) > (Number(j.spam_threshold||4) * 0.9)));

    const alerts = [];
    if((st||'').toLowerCase() === 'backoff') alerts.push('⚠ backoff');
    if(Number(j.chunks_abandoned||0) > 0) alerts.push('❌ abandoned chunks');
    if(done >= 20 && failRatio >= 0.1) alerts.push('⚠ high fail rate');
    if(nearSpam) alerts.push('⚠ spam near limit');

    const quickEl = qk(card,'quickIssues');
    if(alerts.length){
      const txt = 'Quick issues: ' + alerts.join(' · ');
      alertsEl.textContent = txt;
      alertsEl.style.display = '';
      if(quickEl) quickEl.textContent = txt;
    }else{
      alertsEl.textContent = '';
      alertsEl.style.display = 'none';
      if(quickEl) quickEl.textContent = '';
    }

    // Notifications
    const pm = j.pmta_live || null;
    const pmStateNow = (pm && pm.enabled)
      ? (pm.ok ? 'ok' : 'bad')
      : 'disabled';
    const pmStatePrev = state.lastPmtaMonitor[jobId];
    if(pmStatePrev !== pmStateNow){
      if(pmStateNow === 'ok'){
        toast('✅ PowerMTA Monitor connected', `Job ${jobId}: Live monitor connection is active.`, 'good');
      }else if(pmStateNow === 'bad'){
        toast('❌ PowerMTA Monitor disconnected', `Job ${jobId}: ${pm?.reason || 'Monitor unreachable.'}`, 'bad');
      }
      state.lastPmtaMonitor[jobId] = pmStateNow;
    }

    const prevStatus = state.lastStatus[jobId];
    if(prevStatus && prevStatus !== st){
      if((st||'').toLowerCase() === 'backoff') toast('Backoff', `Job ${jobId} entered backoff.`, 'warn');
      if((st||'').toLowerCase() === 'done') toast('Done', `Job ${jobId} finished.`, 'good');
      if((st||'').toLowerCase() === 'error') toast('Error', `Job ${jobId} errored: ${j.last_error || ''}`, 'bad');
      if((st||'').toLowerCase() === 'stopped') toast('Stopped', `Job ${jobId} stopped: ${j.stop_reason || ''}`, 'warn');
      if((st||'').toLowerCase() === 'paused') toast('Paused', `Job ${jobId} paused.`, 'warn');
      if((st||'').toLowerCase() === 'running' && (prevStatus||'').toLowerCase() === 'paused') toast('Resumed', `Job ${jobId} resumed.`, 'good');
    }
    state.lastStatus[jobId] = st;

    const prevAb = Number(state.lastAbandoned[jobId] || 0);
    const abNow = Number(j.chunks_abandoned || 0);
    if(abNow > prevAb){
      toast('Abandoned chunk', `Job ${jobId}: abandoned_chunks=${abNow}`, 'bad');
    }
    state.lastAbandoned[jobId] = abNow;

    const prevBf = Number(state.lastBackoff[jobId] || 0);
    const bfNow = Number(j.chunks_backoff || 0);
    if(bfNow > prevBf){
      toast('Backoff event', `Job ${jobId}: backoff_events=${bfNow}`, 'warn');
    }
    state.lastBackoff[jobId] = bfNow;

    const prevFail = Number(state.lastFailed[jobId] || 0);
    const failNow = Number(j.failed || 0);
    if(failNow > prevFail && done >= 20 && failRatio >= 0.1){
      toast('High fail rate', `Job ${jobId}: failed=${failNow}/${done} (${Math.round(failRatio*100)}%)`, 'warn');
    }
    state.lastFailed[jobId] = failNow;

    // Adaptive pressure toasts (health/accounting-driven)
    try{
      const liveRef = getLiveChunks(j);
      const adaptiveRef = liveRef.find(x => x && x.adaptive_health && x.adaptive_health.ok) || liveRef[0] || (j.current_chunk_info || {});
      const ah = (adaptiveRef && adaptiveRef.adaptive_health) ? adaptiveRef.adaptive_health : null;
      if(ah && ah.ok){
        const targetDomain = ((adaptiveRef && (adaptiveRef.target_domain || adaptiveRef.receiver_domain)) || '').toString();
        const signature = [
          Number(ah.level || 0),
          !!ah.reduced,
          (ah.action || '').toString(),
          JSON.stringify(ah.applied || {}),
          (ah.reason || '').toString(),
          targetDomain
        ].join('|');
        if(signature && state.lastAdaptive[jobId] !== signature){
          if(ah.reduced){
            const ap = ah.applied || {};
            toast(
              'Adaptive throttle',
              `Job ${jobId}${targetDomain ? (' · ' + targetDomain) : ''}: reduced pressure (L${Number(ah.level||0)}) · workers=${Number(ap.workers||0)} chunk=${Number(ap.chunk_size||0)} delay=${Number(ap.delay_s||0)}s`,
              'warn'
            );
          }else if((ah.action || '') === 'speed_up'){
            toast('Adaptive speed-up', `Job ${jobId}: healthy delivery, increasing throughput gradually.`, 'good');
          }
          state.lastAdaptive[jobId] = signature;
        }
      }
    }catch(e){ /* ignore */ }

    // Route/IP/domain switch toast per provider domain
    try{
      const routeRows = getLiveChunks(j);
      const seenRouteKeys = new Set();
      for(const ci2 of routeRows){
        const pDom = (ci2.target_domain || ci2.receiver_domain || '').toString();
        const senderNow = (ci2.sender || ci2.sender_mail || '').toString();
        if(!pDom || !senderNow) continue;
        const key = `${jobId}:${pDom}`;
        if(seenRouteKeys.has(key)) continue;
        seenRouteKeys.add(key);
        const prevSender = (state.lastRoute[key] || '').toString();
        if(prevSender && prevSender !== senderNow){
          toast('Route switched', `Provider ${pDom}: switched sender/IP from ${prevSender} to ${senderNow}.`, 'warn');
        }
        state.lastRoute[key] = senderNow;
      }
    }catch(e){ /* ignore */ }

    // Disable/enable controls based on state
    const btnPause = card.querySelector('[data-action="pause"]');
    const btnResume = card.querySelector('[data-action="resume"]');
    const btnStop = card.querySelector('[data-action="stop"]');
    if(btnPause) btnPause.disabled = !!j.paused || (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'error' || (st||'').toLowerCase() === 'stopped';
    if(btnResume) btnResume.disabled = !j.resumable || !j.paused || (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'stopped';
    if(btnStop) btnStop.disabled = (st||'').toLowerCase() === 'done' || (st||'').toLowerCase() === 'error' || (st||'').toLowerCase() === 'stopped';

    state.lastJobPayload[jobId] = j;
    renderBridgeReceiver(card, j, state.latestBridgeState);
    applyFiltersAndSort();
  }

  async function tickCard(card){
    const jobId = card.dataset.jobid;
    try{
      const r = await fetch(`/api/job/${jobId}`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && !j.error){
        updateCard(card, j);
      }
    }catch(e){
      // ignore
    }
  }

  function bindControls(card){
    const jobId = card.dataset.jobid;
    const btns = card.querySelectorAll('button[data-action]');
    btns.forEach(b => {
      b.addEventListener('click', () => {
        const action = b.getAttribute('data-action');
        if(action === 'delete'){
          deleteJob(jobId, card);
          return;
        }
        controlJob(jobId, action);
      });
    });
  }

  function bindDetailState(card){
    const jobId = card.dataset.jobid;
    const more = card.querySelector('details.more');
    if(!jobId || !more) return;
    const storageKey = `jobs-more-${jobId}`;
    try{
      if(sessionStorage.getItem(storageKey) === '1'){
        more.open = true;
      }
    }catch(e){ /* ignore */ }
    more.addEventListener('toggle', () => {
      try{
        sessionStorage.setItem(storageKey, more.open ? '1' : '0');
      }catch(e){ /* ignore */ }
    });
  }

  function updateFilterUrl(){
    try{
      const u = new URL(window.location.href);
      const keep = (key, val) => {
        if(!val || val === 'all' || (key === 'sort' && val === 'newest')) u.searchParams.delete(key);
        else u.searchParams.set(key, val);
      };
      keep('status', state.filters.status);
      keep('mode', state.filters.mode);
      keep('risk', state.filters.risk);
      keep('provider', state.filters.provider);
      keep('sort', state.filters.sort);
      history.replaceState(null, '', `${u.pathname}?${u.searchParams.toString()}`.replace(/\?$/, ''));
    }catch(e){ /* ignore */ }
  }

  function restoreFiltersFromQuery(){
    try{
      const p = new URLSearchParams(window.location.search || '');
      const get = (k, d) => (p.get(k) || d).toString().trim().toLowerCase();
      const status = get('status', 'all');
      const mode = get('mode', 'all');
      const risk = get('risk', 'all');
      const provider = get('provider', 'all');
      const sort = get('sort', 'newest');
      state.filters.status = ['all','running','done','paused','backoff','stop'].includes(status) ? status : 'all';
      state.filters.mode = ['all','counts','legacy'].includes(mode) ? mode : 'all';
      state.filters.risk = ['all','internal_degraded','deliverability_high','stale'].includes(risk) ? risk : 'all';
      state.filters.provider = ['all','gmail','yahoo','outlook','icloud','other'].includes(provider) ? provider : 'all';
      state.filters.sort = ['newest','highest_risk','stalest'].includes(sort) ? sort : 'newest';
    }catch(e){ /* ignore */ }
  }

  function syncFilterInputs(){
    const bind = (id, key) => {
      const el = document.getElementById(id);
      if(!el) return;
      el.value = state.filters[key];
      el.addEventListener('change', () => {
        state.filters[key] = (el.value || 'all').toString().trim().toLowerCase();
        applyFiltersAndSort();
        updateFilterUrl();
      });
    };
    bind('fltStatus', 'status');
    bind('fltMode', 'mode');
    bind('fltRisk', 'risk');
    bind('fltProvider', 'provider');
    bind('fltSort', 'sort');
  }

  function passesRiskFilter(j){
    if(state.filters.risk === 'all') return true;
    if(state.filters.risk === 'internal_degraded') return hasInternalDegraded(j);
    if(state.filters.risk === 'deliverability_high') return hasDeliverabilityHigh(j);
    if(state.filters.risk === 'stale') return isStaleJob(j);
    return true;
  }

  function applyFiltersAndSort(){
    const rows = cards.map((card, idx) => {
      const jobId = (card.dataset.jobid || '').toString();
      const fallbackStatus = ((qk(card, 'status') && qk(card, 'status').textContent) || '').toString().trim().toLowerCase();
      const j = state.lastJobPayload[jobId] || { status: fallbackStatus, created_at: card.dataset.created || '' };
      return { card, idx, job: j };
    });

    const visible = [];
    for(const row of rows){
      const j = row.job || {};
      const statusOk = state.filters.status === 'all' || normalizeJobStatus(j) === state.filters.status;
      const modeOk = state.filters.mode === 'all' || normalizeBridgeMode(j) === state.filters.mode;
      const riskOk = passesRiskFilter(j);
      const providerOk = state.filters.provider === 'all' || detectProviderBucket(j) === state.filters.provider;
      const keep = statusOk && modeOk && riskOk && providerOk;
      row.card.style.display = keep ? '' : 'none';
      if(keep) visible.push(row);
    }

    const createdMs = (row) => {
      const ms = tsToMs(row.job.created_at || row.card.dataset.created || '');
      return Number.isFinite(ms) ? ms : 0;
    };
    const staleMin = (row) => {
      const v = freshnessMinutes(row.job);
      return Number.isFinite(v) ? v : -1;
    };
    visible.sort((a,b) => {
      if(state.filters.sort === 'highest_risk'){
        const d = riskRank(b.job) - riskRank(a.job);
        if(d !== 0) return d;
      }else if(state.filters.sort === 'stalest'){
        const d = staleMin(b) - staleMin(a);
        if(d !== 0) return d;
      }
      const byNew = createdMs(b) - createdMs(a);
      if(byNew !== 0) return byNew;
      return a.idx - b.idx;
    });

    const parent = cards[0] ? cards[0].parentElement : null;
    if(parent){
      for(const row of visible){ parent.appendChild(row.card); }
    }

    const empty = document.getElementById('jobsFilteredEmpty');
    if(empty) empty.style.display = (cards.length > 0 && visible.length === 0) ? '' : 'none';

    const listEmpty = document.getElementById('jobsListEmpty');
    if(listEmpty) listEmpty.style.display = cards.length === 0 ? '' : 'none';

    const meta = document.getElementById('filterMeta');
    if(meta){
      const total = cards.length;
      const shown = visible.length;
      meta.textContent = shown === total
        ? `Showing all ${total} job${total === 1 ? '' : 's'}.`
        : `Showing ${shown} of ${total} job${total === 1 ? '' : 's'}.`;
    }
  }

  function setFilterDrawerOpen(open){
    const isOpen = !!open;
    document.body.classList.toggle('filterMenuOpen', isOpen);
    const drawer = document.getElementById('jobsFilterDrawer');
    if(drawer) drawer.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
  }

  function bindFilterDrawer(){
    const btn = document.getElementById('btnToggleFilters');
    const backdrop = document.getElementById('jobsFilterBackdrop');
    if(btn){
      btn.addEventListener('click', () => {
        const isOpen = document.body.classList.contains('filterMenuOpen');
        setFilterDrawerOpen(!isOpen);
      });
    }
    if(backdrop){
      backdrop.addEventListener('click', () => setFilterDrawerOpen(false));
    }
    document.addEventListener('keydown', (ev) => {
      if(ev.key === 'Escape') setFilterDrawerOpen(false);
    });
  }

  restoreFiltersFromQuery();
  syncFilterInputs();
  bindFilterDrawer();

  let cards = Array.from(document.querySelectorAll('.job[data-jobid]'));
  cards.forEach(bindControls);
  cards.forEach(bindDetailState);

  async function tickAll(){
    for(const c of cards){
      await tickCard(c);
    }
    applyFiltersAndSort();
  }

  async function bridgeDebugTick(){
    try{
      const r = await fetch('/api/accounting/ssh/status');
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.bridge){
        const b = j.bridge || {};
        state.latestBridgeState = b;
        cards.forEach(card => {
          const jid = (card.dataset.jobid || "").toString();
          const snapshot = state.lastJobPayload[jid];
          renderBridgeConnectionBadge(card, b);
          if(snapshot) renderBridgeReceiver(card, snapshot, b);
        });
        console.log('[Bridge↔Shiva Debug]', {
          connected: !!b.connected,
          last_ok: !!b.last_ok,
          last_error: b.last_error || '',
          last_attempt_ts: b.last_attempt_ts || '',
          last_success_ts: b.last_success_ts || '',
          attempts: Number(b.attempts || 0),
          success_count: Number(b.success_count || 0),
          failure_count: Number(b.failure_count || 0),
          req_url: b.last_req_url || b.pull_url_masked || '',
          bridge_return_keys: Array.isArray(b.last_response_keys) ? b.last_response_keys : [],
          bridge_return_count: Number(b.last_bridge_count || 0),
          processed_by_shiva: Number(b.last_processed || 0),
          accepted_by_shiva: Number(b.last_accepted || 0),
          lines_sample: Array.isArray(b.last_lines_sample) ? b.last_lines_sample : [],
          duration_ms: Number(b.last_duration_ms || 0),
        });
      } else {
        console.warn('[Bridge↔Shiva Debug] bridge status failed', {http_status: r.status, payload: j});
      }
    }catch(e){
      state.latestBridgeState = null;
      cards.forEach(card => {
        const jid = (card.dataset.jobid || "").toString();
        const snapshot = state.lastJobPayload[jid] || {};
        renderBridgeConnectionBadge(card, null);
        renderBridgeReceiver(card, snapshot, null);
      });
      console.error('[Bridge↔Shiva Debug] bridge status exception', e);
    }
  }

  function _fmtTsAge(ts){
    const raw = (ts || '').toString().trim();
    if(!raw) return '—';
    const mins = ageMin(raw);
    if(mins === null) return esc(raw);
    if(mins < 1) return `${esc(raw)} (just now)`;
    if(mins < 60) return `${esc(raw)} (${mins}m ago)`;
    const h = Math.floor(mins / 60);
    const m = mins % 60;
    return `${esc(raw)} (${h}h ${m}m ago)`;
  }

  function _shortCursor(v){
    const raw = (v || '').toString().trim();
    if(!raw) return '—';
    if(raw.length <= 44) return raw;
    return `${raw.slice(0, 22)}…${raw.slice(-16)}`;
  }

  function renderBridgeReceiver(card, j, b){
    const el = qk(card, 'bridgeReceiver');
    if(!el){ return; }

    const modeRaw = (j && j.bridge_mode ? j.bridge_mode : (b && b.bridge_mode ? b.bridge_mode : 'counts')).toString().trim().toLowerCase();
    const isLegacy = modeRaw === 'legacy';
    const isCounts = !isLegacy;

    const pollSuccessTs = (j && j.bridge_last_success_ts) || (b && b.last_success_ts) || '';
    const accountingTs = (j && j.accounting_last_update_ts) || (j && j.accounting_last_ts) || '';

    if(isCounts){
      el.innerHTML = [
        'Data source: <b>Bridge snapshot</b>',
        `Last poll success: <b>${_fmtTsAge(pollSuccessTs)}</b>`,
        `Last accounting update: <b>${_fmtTsAge(accountingTs)}</b>`,
      ].join('<br>');
      return;
    }

    const hasMore = !!(j && j.bridge_has_more);
    const cursorShort = _shortCursor((j && j.bridge_last_cursor) || '');
    const received = Number((j && j.received) || 0);
    const ingested = Number((j && j.ingested) || 0);
    const duplicates = Number((j && j.duplicates_dropped) || 0);
    const notFound = Number((j && j.job_not_found) || 0);
    const lagSecRaw = Number(j && j.ingestion_lag_seconds);
    const lagMins = Number.isFinite(lagSecRaw) && lagSecRaw >= 0
      ? Math.floor(lagSecRaw / 60)
      : ageMin((j && j.ingestion_last_event_ts) || '');
    const lagTxt = (lagMins === null) ? '—' : (lagMins <= 1 ? 'caught up' : `${lagMins}m`);

    el.innerHTML = [
      'Data source: <b>Event ingestion</b>',
      `Cursor progress: has_more=<b>${hasMore ? 'yes' : 'no'}</b> · last_cursor=<code>${esc(cursorShort)}</code>`,
      `Ingestion stats: received=<b>${received}</b> · ingested=<b>${ingested}</b> · duplicates=<b>${duplicates}</b> · job_not_found=<b>${notFound}</b>`,
      `Ingestion last event: <b>${_fmtTsAge((j && j.ingestion_last_event_ts) || '')}</b> · lag: <b>${esc(lagTxt)}</b>`,
    ].join('<br>');
  }


  document.getElementById('btnRefreshAll')?.addEventListener('click', tickAll);

  applyFiltersAndSort();
  tickAll();
  bridgeDebugTick();
  setInterval(tickAll, 1200);
  setInterval(bridgeDebugTick, 5000);
</script>

</body></html>
"""

SEND_PAGE_BODY = r"""
<div class="wrap">
  <div class="top">
    <div>
      <h1>SMTP Mail Sender · <span style="color: var(--muted)">Campaign {{ campaign_ts }}</span></h1>
      <div class="sub">
        A simple, clean UI to send email via SMTP with a progress bar and logs.
        <br>
        <b style="color: var(--warn)">⚠️ Legal use only:</b> send to opt-in/permission-based recipients.
      </div>
    </div>
    <div class="topActions">
      <a class="badge" href="/campaigns">📌 Campaigns</a>
    </div>
  </div>

  <form class="grid send-layout" method="post" action="/start" enctype="multipart/form-data" id="mainForm">
    <input type="hidden" name="campaign_id" value="abac50d078ae">
    <div class="stack">
      <div class="card">
      <h2>SMTP Settings</h2>

      <div class="row">
        <div>
          <label>SMTP Host</label>
          <input name="smtp_host" placeholder="Example: mail.example.com or an IP" required="">
        </div>
        <div>
          <label>Port</label>
          <input name="smtp_port" type="number" placeholder="Example: 25 / 2525 / 587 / 465" required="" value="2525">
        </div>
      </div>

      <div class="row">
        <div>
          <label>Security</label>
          <select name="smtp_security">
            <option value="starttls">STARTTLS (587)</option>
            <option value="ssl">SSL/TLS (465)</option>
            <option value="none" selected="">None (not recommended)</option>
          </select>
        </div>
        <div>
          <label>Timeout (seconds)</label>
          <input name="smtp_timeout" type="number" value="25" min="5" max="120">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SMTP Username (optional)</label>
          <input name="smtp_user" placeholder="Example: user@example.com">
        </div>
        <div>
          <label>SMTP Password (optional)</label>
          <input name="smtp_pass" type="password" placeholder="••••••••">
        </div>
      </div>

      <div class="check" style="margin-top:10px">
        <input type="checkbox" id="remember_pass" name="remember_pass">
        <div>
          Remember SMTP password on this browser (saved in server database (SQLite)). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
        </div>
      </div>

      <div class="hint">
        <b>Note:</b> If you use PowerMTA or a custom SMTP server, set the correct host and port.
        Usually: <code>587 + STARTTLS</code> or <code>465 + SSL/TLS</code>.
        <br>
        ✅ <b>Test SMTP</b> only connects (and authenticates if provided) — <b>it does not send any email</b>.
      </div>

      <div class="actions">
        <button class="btn secondary" type="button" id="btnTest">🔌 Test SMTP</button>
        <div class="mini" id="testMini">Test the connection before sending.</div>
      </div>
      <div class="inline-status" id="smtpTestInline"></div>
      </div>

      <div class="card">
      <h2>SSH Connection</h2>

      <div class="row">
        <div>
          <label>SSH Host</label>
          <input name="ssh_host" placeholder="Example: same PMTA server host/IP">
        </div>
        <div>
          <label>SSH Port</label>
          <input name="ssh_port" type="number" placeholder="22" value="22">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SSH Username</label>
          <input name="ssh_user" placeholder="Example: root or pmtaops">
        </div>
        <div>
          <label>SSH Key Path (optional)</label>
          <input name="ssh_key_path" placeholder="/home/app/.ssh/id_rsa">
        </div>
      </div>

      <div class="row">
        <div>
          <label>SSH Password (optional)</label>
          <input name="ssh_pass" type="password" placeholder="Password auth supported directly by Shiva">
        </div>
        <div>
          <label>SSH Timeout (seconds)</label>
          <input name="ssh_timeout" type="number" value="8" min="3" max="120">
        </div>
      </div>

      <div class="check" style="margin-top:10px">
        <input type="checkbox" id="remember_ssh_pass" name="remember_ssh_pass">
        <div>
          Remember SSH password on this browser (saved in server database (SQLite)). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
        </div>
      </div>

      <div class="hint">
        <b>PMTA monitoring/accounting now uses SSH only.</b> Shiva runs commands such as <code>pmta show status</code> and tails the remote accounting CSV via SSH.
      </div>

      <div class="actions">
        <button class="btn secondary" type="button" id="btnSshTest">🖧 Test SSH</button>
        <div class="mini">Checks SSH access and runs <code>pmta show status</code>.</div>
      </div>
      <div class="inline-status" id="sshTestInline"></div>
      </div>

      <div class="card">
        <h2>Preflight &amp; Send Controls</h2>

        <div class="check">
        <input type="checkbox" name="permission_ok" required="">
        <div>
          I confirm this recipient list is <b>permission-based (opt-in)</b> and this usage is lawful.
          (Sending is blocked without this confirmation.)
        </div>
      </div>

      <div class="hint" id="preflightBox" style="margin-top:12px">
        <b>Preflight stats (optional):</b> get the <b>Spam score</b> + check if the <b>sender domain / SMTP IP</b> is blacklisted.
        <div class="row" style="margin-top:10px">
          <div>
            <div class="mini"><b>Spam score:</b> <span id="pfSpam">—</span></div>
            <div class="mini" id="pfSpamMore" style="display:none"></div>
          </div>
          <div>
            <div class="mini"><b>Blacklist:</b> <span id="pfBl">—</span></div>
            <div class="mini" id="pfBlMore" style="display:none"></div>
          </div>
        </div>
        <div class="mini" style="margin-top:10px"><b>Sender domains status:</b> Domain → IP(s) → Listed/Not listed</div>
        <div style="overflow:auto; margin-top:8px">
          <table style="width:100%; border-collapse:collapse; font-size:12px">
            <thead>
              <tr>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Domain</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">IP(s)</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Status</th>
                <th style="text-align:left; padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">Spam score (per domain)</th>
              </tr>
            </thead>
            <tbody id="pfDomains">
              <tr><td colspan="4" class="muted" style="padding:6px">Run Preflight to see sender domains.</td></tr>
            </tbody>
          </table>
        </div>

        <div class="actions" style="margin-top:10px">
          <button class="btn secondary" type="button" id="btnPreflight">📊 Preflight Check</button>
          <div class="mini">Uses SpamAssassin backend (if available) + DNSBL checks (server-side).</div>
        </div>

        <div class="hint" style="margin-top:10px">
          <b>Sending controls:</b> these settings affect the real sending job.
          <div class="mini">Rule: <b>one chunk uses one sender email</b> (rotated by chunk index). Each chunk can use many workers.</div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Delay between messages (seconds)</label>
              <input name="delay_s" type="number" value="0.0" step="0.1" min="0" max="10">
            </div>
            <div>
              <label>Max Recipients (safety)</label>
              <input name="max_rcpt" type="number" value="300" min="1" max="200000">
            </div>
          </div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Thread chunk size</label>
              <input name="chunk_size" type="number" value="50" min="1" max="50000">
              <div class="mini">Recipients are split into chunks of this size. Each chunk picks one sender email.</div>
            </div>
            <div>
              <label>Thread workers</label>
              <input name="thread_workers" type="number" value="5" min="1" max="200">
              <div class="mini">Workers send in parallel inside the same chunk (one SMTP connection per worker).</div>
            </div>
          </div>

          <div class="row" style="margin-top:10px">
            <div>
              <label>Sleep between chunks (seconds)</label>
              <input name="sleep_chunks" type="number" value="0.0" step="0.1" min="0" max="120">
            </div>
            <div>
              <div class="mini" style="margin-top:26px">Tip: start with <b>chunk size 20–100</b> and <b>workers 2–10</b>.</div>
            </div>
          </div>
        </div>

        <div class="hint" style="margin-top:10px">
            <b>AI rewrite (optional):</b> rewrite subject/body for clarity (requires OpenRouter token).
            <div class="row" style="margin-top:10px">
              <div>
                <label>AI Token (OpenRouter)</label>
                <input name="ai_token" type="password" placeholder="sk-or-..." autocomplete="off">
                <div class="mini">Token is not saved unless you enable the checkbox below.</div>
              </div>
              <div>
                <label>&nbsp;</label>
                <div class="check" style="margin-top:0">
                  <input type="checkbox" name="use_ai" id="use_ai">
                  <div>
                    Use AI rewrite before sending (applies once per job).
                  </div>
                </div>
                <div class="check" style="margin-top:10px">
                  <input type="checkbox" id="remember_ai" name="remember_ai">
                  <div>
                    Remember AI token on this browser (server database / SQLite). <b style="color: var(--warn)">Not recommended</b> on shared PCs.
                  </div>
                </div>
              </div>
            </div>
            <div class="actions" style="margin-top:10px">
              <button class="btn secondary" type="button" id="btnAiRewrite">🤖 Rewrite Now</button>
              <div class="mini" id="aiMini">Rewrites the current Subject lines + Body and fills the fields (review before sending).</div>
            </div>
          </div>

        
      </div>
      </div>
    </div>

    <div class="card">
      <h2>Message</h2>

      <div class="row">
        <div>
          <label>Sender Name</label>
          <textarea name="from_name" placeholder="Example: Ahmed (one per line)" required="" style="min-height:48px"></textarea>
        </div>
        <div>
          <label>Sender Email</label>
          <textarea name="from_email" placeholder="Example: sender@domain.com (one per line)" required="" style="min-height:48px"></textarea>
        </div>
      </div>

      <label>Subject</label>
      <textarea name="subject" placeholder="Email subject (one per line)" required="" style="min-height:48px"></textarea>

      <div class="row">
        <div>
          <label>Format</label>
          <select name="body_format">
            <option value="text" selected="">Text</option>
            <option value="html">HTML</option>
          </select>
          <div class="mini">If you choose HTML, the email will be sent as HTML.</div>
        </div>
        <div>
          <label>Reply-To (optional)</label>
          <input name="reply_to" placeholder="reply@domain.com">
        </div>
      </div>

      <label>Spam score limit</label>
      <input type="range" class="form-range" min="1" max="10" value="4" step="0.5" style="width: 100%;" name="score_range" id="score_range">
      <div class="mini">Current limit: <b id="score_range_val">4.0</b> (sending is blocked if spam score is higher)</div>

      <label>Body</label>
      <textarea name="body" placeholder="Write your message here..." required=""></textarea>

      <div class="row" style="margin-top:10px">
        <div>
          <label>URL list (one per line)</label>
          <textarea name="urls_list" placeholder="https://example.com/a
https://example.com/b" style="min-height:90px"></textarea>
          <div class="mini">Use <code>[URL]</code> in subject/body. Replaced per chunk in line order (cycles back to first line after the last).</div>
        </div>
        <div>
          <label>SRC list (one per line)</label>
          <textarea name="src_list" placeholder="https://cdn.example.com/img1.png
https://cdn.example.com/img2.png" style="min-height:90px"></textarea>
          <div class="mini">Use <code>[SRC]</code> in subject/body. Replaced per chunk in line order (cycles back to first line after the last). Use <code>[MAIL]</code> or <code>[EMAIL]</code> for recipient email, and <code>[NAME]</code> for the part before @.</div>
        </div>
      </div>

      <h2 style="margin-top:14px">Recipients</h2>

      <label>Recipients (newline / comma / semicolon)</label>
      <textarea name="recipients" placeholder="a@x.com
b@y.com
c@z.com"></textarea>

      <label>Or upload a .txt or .csv file (single column or multiple columns)</label>
      <input type="file" name="recipients_file" accept=".txt,.csv">

      <label>Maillist Safe (optional whitelist)</label>
      <textarea name="maillist_safe" placeholder="If set, ONLY these emails will receive (newline / comma / semicolon)"></textarea>
      <div class="mini">If this field is filled, recipients not in this list will be skipped.</div>

      <div class="hint">
        ✅ This tool will:
        <ul style="margin:8px 0 0; padding:0 18px; color: rgba(255,255,255,.62)">
          <li>Clean &amp; deduplicate recipients</li>
          <li>Filter invalid emails</li>
          <li>Show progress + logs</li>
        </ul>
      </div>

      <div class="actions">
        <button class="btn" type="submit" id="btnStart">🚀 Start Sending</button>
        <a class="btn secondary" href="/jobs?c=abac50d078ae" style="text-decoration:none; display:inline-block;">📄 Jobs</a>
        <a class="btn secondary" href="/campaign/abac50d078ae/config" style="text-decoration:none; display:inline-block;">⚙️ Config</a>
      </div>

      <div class="foot">
        Tip: test first with 2–5 emails to confirm SMTP settings before sending large batches.
      </div>
    </div>
  </form>

  <div class="card" id="domainsCard" style="margin-top:14px">
    <h2>Save Domains</h2>

    <div class="actions" style="margin-top:12px">
      <input id="domQ" placeholder="Search domain..." style="max-width:320px">
      <button class="btn secondary" type="button" id="btnDomains" disabled="">🌐 Refresh</button>
      <div class="mini" id="domStatus">Loading...</div>
    </div>

    <div class="hint" style="margin-top:12px">
      <div class="mini"><b>Safe domains:</b> <span id="domSafeTotals">—</span></div>
    </div>

    <div style="overflow:auto; margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Sender domain</th>
            <th>Emails</th>
            <th>MX</th>
            <th>MX hosts</th>
            <th>Mail IP(s)</th>
            <th>Listed</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>DMARC</th>
          </tr>
        </thead>
        <tbody id="domTblSafe">
          <tr><td colspan="9" class="muted">—</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast-wrap" id="toastWrap"></div>
"""

SEND_PAGE_SCRIPT = r"""
function q(name){ return document.querySelector(`[name="${name}"]`); }

  function labelForElement(el){
    if(!el) return '';
    const raw = (el.textContent || '').replace(/\s+/g, ' ').trim();
    return raw.replace(/^[-•\s]+/, '');
  }

  // -------------------------
  // Persist form values (SQLite via server API)
  // -------------------------

  const CAMPAIGN_ID = "abac50d078ae";
  let __sendSubmitting = false;  // prevent double-submit while a job is being created

  async function apiGetForm(){
    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/form`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok && j.data && typeof j.data === 'object'){
        return j.data;
      }
    }catch(e){ /* ignore */ }
    return {};
  }

  async function apiSaveForm(data){
    try{
      await fetch(`/api/campaign/${CAMPAIGN_ID}/form`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({data: data || {}})
      });
    }catch(e){ /* ignore */ }
  }

  async function apiClearForm(scope){
    try{
      await fetch(`/api/campaign/${CAMPAIGN_ID}/clear`, {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({scope: scope || 'mine'})
      });
    }catch(e){ /* ignore */ }
  }

  function formFields(){
    return document.querySelectorAll('#mainForm input, #mainForm textarea, #mainForm select');
  }

  async function loadSavedForm(){
    const data = await apiGetForm();
    for(const [k,v] of Object.entries(data || {})){
      const el = q(k);
      if(!el) continue;
      if(el.type === 'file') continue;
      if(el.type === 'checkbox'){
        el.checked = !!v;
      }else{
        el.value = (v ?? '').toString();
      }
    }
  }

  async function saveFormNow(){
    const data = {};
    const rememberPass = document.getElementById('remember_pass')?.checked;

    formFields().forEach(el => {
      const name = el.name;
      if(!name) return;
      if(el.type === 'file') return;

      if(el.type === 'password'){
        // Only store secrets if user explicitly opts in.
        if(name === 'smtp_pass'){
          data[name] = rememberPass ? (el.value || '') : '';
          return;
        }
        if(name === 'ssh_pass'){
          const rememberSsh = document.getElementById('remember_ssh_pass')?.checked;
          data[name] = rememberSsh ? (el.value || '') : '';
          return;
        }
        if(name === 'ai_token'){
          const rememberAi = document.getElementById('remember_ai')?.checked;
          data[name] = rememberAi ? (el.value || '') : '';
          return;
        }
        data[name] = '';
        return;
      }

      if(el.type === 'checkbox'){
        data[name] = !!el.checked;
        return;
      }

      data[name] = (el.value ?? '').toString();
    });

    data.__ts = Date.now();
    await apiSaveForm(data);
  }

  let _saveTimer = null;
  function scheduleSave(){
    if(_saveTimer) clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => { saveFormNow(); }, 250);
  }

  function escHtml(s){
    return (s ?? '').toString()
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'",'&#39;');
  }

  function toast(title, msg, kind){
    const wrap = document.getElementById('toastWrap');
    const div = document.createElement('div');
    div.className = `toast ${kind || 'warn'}`;
    const safeTitle = escHtml(title);
    const safeMsg = escHtml(msg).split(/\r?\n/).join("<br>");
    div.innerHTML = `<div class="t">${safeTitle}</div><div>${safeMsg}</div>`;
    wrap.appendChild(div);
    setTimeout(() => {
      div.style.opacity = '0';
      div.style.transform = 'translateY(6px)';
      div.style.transition = 'all .22s ease';
      setTimeout(()=>div.remove(), 260);
    }, 3600);
  }

  function setInline(html, kind){
    const box = document.getElementById('smtpTestInline');
    box.classList.add('show');
    box.style.borderColor = kind === 'good' ? 'rgba(53,228,154,.35)' : (kind === 'bad' ? 'rgba(255,94,115,.35)' : 'rgba(255,193,77,.35)');
    box.innerHTML = html;
  }

  async function doSmtpTest(){
    const btn = document.getElementById('btnTest');
    btn.disabled = true;

    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      smtp_port: (q('smtp_port')?.value || '').trim(),
      smtp_security: (q('smtp_security')?.value || 'none').trim(),
      smtp_timeout: (q('smtp_timeout')?.value || '25').trim(),
      smtp_user: (q('smtp_user')?.value || '').trim(),
      smtp_pass: (q('smtp_pass')?.value || '').trim(),
    };

    if(!payload.smtp_host || !payload.smtp_port){
      toast('SMTP Test', 'Please enter Host and Port first.', 'warn');
      setInline('<b>SMTP Test:</b> Please enter Host and Port first.', 'warn');
      btn.disabled = false;
      return;
    }

    toast('SMTP Test', 'Testing connection...', 'warn');
    setInline('<b>SMTP Test:</b> Testing connection...', 'warn');

    try{
      const r = await fetch('/api/smtp_test', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));

      if(r.ok && j.ok){
        toast('✅ SMTP OK', j.detail || 'Connection successful', 'good');
        setInline(`<b>SMTP OK</b><br>• ${j.detail || ''}<br>• Time: <b>${j.time_ms || 0}ms</b>`, 'good');
      } else {
        const msg = (j && (j.detail || j.error)) ? (j.detail || j.error) : `HTTP ${r.status}`;
        toast('❌ SMTP Failed', msg, 'bad');
        setInline(`<b>SMTP Failed</b><br>• ${msg}`, 'bad');
      }

    }catch(e){
      toast('❌ SMTP Failed', e?.toString?.() || 'Unknown error', 'bad');
      setInline(`<b>SMTP Failed</b><br>• ${(e?.toString?.() || 'Unknown error')}`, 'bad');
    }finally{
      btn.disabled = false;
    }
  }

  document.getElementById('btnTest').addEventListener('click', doSmtpTest);

  async function doSshTest(){
    const btn = document.getElementById('btnSshTest');
    const box = document.getElementById('sshTestInline');
    const setBox = (html, kind) => {
      box.classList.add('show');
      box.style.borderColor = kind === 'good' ? 'rgba(53,228,154,.35)' : (kind === 'bad' ? 'rgba(255,94,115,.35)' : 'rgba(255,193,77,.35)');
      box.innerHTML = html;
    };

    btn.disabled = true;
    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      ssh_host: (q('ssh_host')?.value || '').trim(),
      ssh_port: (q('ssh_port')?.value || '22').trim(),
      ssh_user: (q('ssh_user')?.value || '').trim(),
      ssh_key_path: (q('ssh_key_path')?.value || '').trim(),
      ssh_pass: (q('ssh_pass')?.value || '').trim(),
      ssh_timeout: (q('ssh_timeout')?.value || '8').trim(),
    };

    try{
      const r = await fetch('/api/ssh_test', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        toast('✅ SSH OK', j.detail || 'SSH connection successful', 'good');
        setBox(`<b>SSH OK</b><br>• ${(j.detail || '')}<br>• Target: <b>${escHtml(j.target || '—')}</b>`, 'good');
      }else{
        const msg = (j && (j.detail || j.error)) ? (j.detail || j.error) : `HTTP ${r.status}`;
        toast('❌ SSH Failed', msg, 'bad');
        setBox(`<b>SSH Failed</b><br>• ${escHtml(msg)}`, 'bad');
      }
    }catch(e){
      const msg = e?.toString?.() || 'Unknown error';
      toast('❌ SSH Failed', msg, 'bad');
      setBox(`<b>SSH Failed</b><br>• ${escHtml(msg)}`, 'bad');
    }finally{
      btn.disabled = false;
    }
  }

  document.getElementById('btnSshTest').addEventListener('click', doSshTest);

  async function doAiRewrite(){
    const btn = document.getElementById('btnAiRewrite');
    if(btn) btn.disabled = true;

    const token = (q('ai_token')?.value || '').trim();

    if(!token){
      toast('AI rewrite', 'Please paste your OpenRouter token first.', 'warn');
      if(btn) btn.disabled = false;
      return;
    }

    const subjText = (q('subject')?.value || '');
    const body = (q('body')?.value || '');
    const body_format = (q('body_format')?.value || 'text');

    toast('AI rewrite', 'Rewriting subject/body...', 'warn');

    try{
      const r = await fetch('/api/ai_rewrite', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          token,
          subjects: subjText.split('\n').map(x=>x.trim()).filter(Boolean),
          body,
          body_format
        })
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j.ok){
        const subjEl = q('subject');
        const bodyEl = q('body');

        // Subjects: accept array or string, sanitize, fallback to current text
        const subjArr = Array.isArray(j.subjects)
          ? j.subjects
          : (typeof j.subjects === 'string' ? [j.subjects] : []);

        const cleaned = subjArr
          .map(x => (x ?? '').toString().trim())
          .filter(x => x && !['undefined','null','none'].includes(x.toLowerCase()));

        if(subjEl){
          if(cleaned.length){
            subjEl.value = cleaned.join('\n');
          } else {
            // keep existing subject if AI didn't return subjects
            subjEl.value = subjText;
          }
        }

        if(bodyEl && typeof j.body === 'string'){
          bodyEl.value = j.body;
        }

        scheduleSave();
        toast('✅ AI rewrite', 'Updated Subject + Body. Review, then send.', 'good');
      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        toast('❌ AI rewrite failed', msg, 'bad');
      }
    }catch(e){
      toast('❌ AI rewrite failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const _aiBtn = document.getElementById('btnAiRewrite');
  if(_aiBtn){ _aiBtn.addEventListener('click', doAiRewrite); }

  async function doPreflight(){
    const btn = document.getElementById('btnPreflight');
    if(btn) btn.disabled = true;

    const payload = {
      smtp_host: (q('smtp_host')?.value || '').trim(),
      from_email: (q('from_email')?.value || ''),
      subject: (q('subject')?.value || ''),
      body_format: (q('body_format')?.value || 'text'),
      body: (q('body')?.value || ''),
      spam_limit: (q('score_range')?.value || '4')
    };

    toast('Preflight', 'Checking spam score + blacklist...', 'warn');

    try{
      const r = await fetch('/api/preflight', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));

      const spamEl = document.getElementById('pfSpam');
      const spamMore = document.getElementById('pfSpamMore');
      const blEl = document.getElementById('pfBl');
      const blMore = document.getElementById('pfBlMore');

      if(!spamEl || !blEl){
        toast('Preflight UI error', 'Missing elements: pfSpam/pfBl. Please refresh the page.', 'bad');
        return;
      }

      if(r.ok && j.ok){
        // spam
        if(j.spam_score !== null && j.spam_score !== undefined){
          const s = Number(j.spam_score);
          const lim = Number(j.spam_threshold);
          spamEl.textContent = s.toFixed(2) + ' (limit ' + lim.toFixed(1) + ')';
          spamEl.style.color = (s <= lim) ? 'var(--good)' : 'var(--bad)';
        }else{
          spamEl.textContent = 'unavailable';
          spamEl.style.color = 'var(--warn)';
        }

        if(j.spam_backend){
          spamMore.style.display = 'block';
          spamMore.textContent = 'Backend: ' + j.spam_backend;
        }else{
          spamMore.style.display = 'none';
        }

        // blacklist summary
        const ipListings = j.ip_listings || {};
        const domListings = j.domain_listings || [];

        // IPs from SMTP host
        const listedIpLines = [];
        for(const [ip, arr] of Object.entries(ipListings)){
          if(arr && arr.length){
            listedIpLines.push(ip + ': ' + arr.map(x=>x.zone).join(', '));
          }
        }

        // Domain DBL (domain-level)
        const domZones = (domListings || []).map(x=>x.zone).filter(Boolean);

        // NEW: Sender domains -> resolve IPs -> check IP DNSBL
        const senderDomainIps = j.sender_domain_ips || {};
        const senderDomainIpListings = j.sender_domain_ip_listings || {};
        const senderDomainDblListings = j.sender_domain_dbl_listings || {};
        const senderDomainSpamScores = j.sender_domain_spam_scores || {};
        const senderDomainSpamBackends = j.sender_domain_spam_backends || {};

        // DBL listings for ALL sender domains
        const senderDblListedLines = [];
        for(const [dom, arr] of Object.entries(senderDomainDblListings)){
          if(arr && arr.length){
            const zones = arr.map(x => (x && x.zone) ? x.zone : '').filter(Boolean);
            if(zones.length){
              senderDblListedLines.push(dom + ': ' + zones.join(', '));
            } else {
              senderDblListedLines.push(dom + ': listed');
            }
          }
        }

        const senderListedLines = [];
        const senderAllLines = [];

        for(const [dom, ips] of Object.entries(senderDomainIps)){
          const ipArr = Array.isArray(ips) ? ips : [];
          if(ipArr.length){
            senderAllLines.push(dom + ' => ' + ipArr.join(', '));
          }
        }

        for(const [dom, ipmap] of Object.entries(senderDomainIpListings)){
          const m = ipmap || {};
          for(const [ip, arr] of Object.entries(m)){
            if(arr && arr.length){
              senderListedLines.push(dom + ' / ' + ip + ': ' + arr.map(x=>x.zone).join(', '));
            }
          }
        }

        // Render table: all sender domains -> resolved IPs -> blacklist status + spam score
        const tb = document.getElementById('pfDomains');
        let anyDomainSpamHigh = false;

        if(tb){
          const domains = Array.isArray(j.sender_domains) ? j.sender_domains : [];
          if(!domains.length){
            tb.innerHTML = `<tr><td colspan="4" class="muted" style="padding:6px">No sender domains found.</td></tr>`;
          } else {
            const rows = [];
            for(const dom of domains){
              const ips = Array.isArray(senderDomainIps[dom]) ? senderDomainIps[dom] : [];
              const ipMap = senderDomainIpListings[dom] || {};
              const dblArr = Array.isArray(senderDomainDblListings[dom]) ? senderDomainDblListings[dom] : [];

              // Blacklist status (Listed/Not listed/Unknown)
              let listed = false;
              if(dblArr && dblArr.length){
                listed = true;
              }
              for(const [ip, arr] of Object.entries(ipMap)){
                if(arr && arr.length){
                  listed = true;
                }
              }

              const status = listed ? 'Listed' : (ips.length ? 'Not listed' : 'Unknown');
              const color = listed ? 'var(--bad)' : (ips.length ? 'var(--good)' : 'var(--warn)');
              const ipText = ips.length ? ips.join(', ') : '—';

              // Spam score per domain
              const scRaw = senderDomainSpamScores[dom];
              let spamText = '—';
              let spamColor = 'var(--warn)';
              if(scRaw !== null && scRaw !== undefined && scRaw !== ''){
                const sc = Number(scRaw);
                const lim = Number(j.spam_threshold);
                if(!Number.isNaN(sc)){
                  spamText = sc.toFixed(2);
                  spamColor = (sc <= lim) ? 'var(--good)' : 'var(--bad)';
                  if(sc > lim) anyDomainSpamHigh = true;
                }
              }

              rows.push(
                `<tr>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">${escHtml(dom)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10)">${escHtml(ipText)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10); color:${color}; font-weight:800">${escHtml(status)}</td>`+
                  `<td style="padding:6px; border-bottom:1px solid rgba(255,255,255,.10); color:${spamColor}; font-weight:800">${escHtml(spamText)}</td>`+
                `</tr>`
              );
            }
            tb.innerHTML = rows.join('');
          }
        }

        const anyListed = (listedIpLines.length > 0) || (domZones.length > 0) || (senderListedLines.length > 0) || (senderDblListedLines.length > 0);

        if(!anyListed){
          blEl.textContent = 'Not listed';
          blEl.style.color = 'var(--good)';
          // Still show resolved domain IPs if available
          if(senderAllLines.length){
            blMore.style.display = 'block';
            blMore.textContent = 'Resolved sender domain IPs: ' + senderAllLines.join(' | ');
          } else {
            blMore.style.display = 'none';
          }
        } else {
          blEl.textContent = 'Listed';
          blEl.style.color = 'var(--bad)';
          const parts = [];
          if(listedIpLines.length){ parts.push('SMTP Host IP: ' + listedIpLines.join(' | ')); }
          if(domZones.length){ parts.push('Sender Domain (DBL): ' + domZones.join(', ')); }
          if(senderDblListedLines.length){ parts.push('All sender domains (DBL): ' + senderDblListedLines.join(' | ')); }
          if(senderListedLines.length){ parts.push('Sender Domain IP (DNSBL): ' + senderListedLines.join(' | ')); }
          if(!senderListedLines.length && senderAllLines.length){ parts.push('Resolved sender domain IPs: ' + senderAllLines.join(' | ')); }
          blMore.style.display = 'block';
          blMore.textContent = parts.join(' · ');
        }

        // toast
        const warn = (j.spam_score !== null && j.spam_score !== undefined && Number(j.spam_score) > Number(j.spam_threshold))
          || anyDomainSpamHigh
          || (listedIpLines.length > 0) || (domZones.length > 0) || (senderListedLines.length > 0) || (senderDblListedLines.length > 0);
        toast('Preflight done', warn ? 'Issues detected. See stats below.' : 'Looks good.', warn ? 'warn' : 'good');

      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        toast('Preflight failed', msg, 'bad');
      }

    }catch(e){
      toast('Preflight failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const _pf = document.getElementById('btnPreflight');
  if(_pf){ _pf.addEventListener('click', doPreflight); }

  // Load saved values on page open
  loadSavedForm().then(() => {
    // One quick save after initial load (helps keep DB in sync with defaults)
    setTimeout(()=>{ saveFormNow(); }, 200);
  });

  // Auto-save on change/input + AJAX submit (stay on page, show toast on errors)
  const form = document.getElementById('mainForm');
  if(form){
    form.addEventListener('input', scheduleSave);
    form.addEventListener('change', scheduleSave);

    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();

      // Hard guard: if we are already submitting, do NOTHING.
      if(__sendSubmitting){
        toast('Please wait', 'A send request is already in progress. Wait until the job is created.', 'warn');
        return;
      }

      const btn = document.getElementById('btnStart');
      __sendSubmitting = true;
      if(btn) btn.disabled = true;

      try{
        await saveFormNow();

        // If campaign already has jobs (stopped/running/etc), confirm with the user.
        let latest = null;
        try{
          const r0 = await fetch(`/api/campaign/${CAMPAIGN_ID}/latest_job`);
          const j0 = await r0.json().catch(()=>({}));
          if(r0.ok && j0 && j0.ok && j0.job){ latest = j0.job; }
        }catch(e){ /* ignore */ }

        let forceNew = false;
        if(latest){
          const st = (latest.status || '').toString().toLowerCase();
          const active = (st === 'queued' || st === 'running' || st === 'backoff' || st === 'paused');
          const msg = active
            ? (`This campaign already has a job in progress:\n`+
               `- ID: ${latest.id}\n`+
               `- Status: ${latest.status}\n\n`+
               `Do you want another job?`)
            : (`This campaign already has job history (latest):\n`+
               `- ID: ${latest.id}\n`+
               `- Status: ${latest.status}\n\n`+
               `Do you want to start a new job?`);

          const yes = confirm(msg);
          if(!yes){
            toast('Cancelled', 'Start sending cancelled.', 'warn');
            return;
          }
          if(active){ forceNew = true; }
        }

        // Start recipient pre-send filter before submitting.
        toast('Maillist filter', 'The filter started verifying addresses before sending....', 'warn');

        // Only NOW show submitting toast (and lock start button) — job creation in progress.
        toast('Sending', 'Submitting... please wait', 'warn');

        const fd = new FormData(form);
        // Mark as ajax so server-side can differentiate if needed.
        fd.append('_ajax', '1');
        if(forceNew){ fd.append('force_new_job', '1'); }

        const r = await fetch('/start', {
          method: 'POST',
          body: fd,
          headers: { 'X-Requested-With': 'fetch' }
        });

        const txt = await r.text();

        if(r.ok){
          // Success: /start redirects to /job/<id>. fetch follows redirects, so r.url becomes the job URL.
          if(r.url && r.url.includes('/job/')){
            window.location.href = r.url;
            return;
          }
          toast('✅ Started', 'Job started successfully.', 'good');
          return;
        }

        // If server blocked due to active job, show a clearer message.
        if(r.status === 409){
          toast('Blocked', txt || 'Active job already running. Please confirm to create another job.', 'warn');
        } else {
          // Error: show toast, stay on the form
          toast('❌ Blocked', txt || ('HTTP ' + r.status), 'bad');
        }

      }catch(e){
        toast('❌ Error', (e?.toString?.() || 'Unknown error'), 'bad');
      }finally{
        __sendSubmitting = false;
        if(btn) btn.disabled = false;
      }
    });
  }

  // Clear-saved button removed (campaign data is auto-saved in SQLite).

  // -------------------------
  // Save domains stats (in-page)
  // -------------------------
  let _domCache = null;

  function domStatusBadge(mx){
    if(mx === 'mx') return '<span style="color:var(--good); font-weight:800">MX</span>';
    if(mx === 'a_fallback') return '<span style="color:var(--warn); font-weight:800">A</span>';
    if(mx === 'none') return '<span style="color:var(--bad); font-weight:800">NONE</span>';
    return '<span style="color:var(--warn); font-weight:800">UNKNOWN</span>';
  }

  function domListedBadge(v){
    return v ? '<span style="color:var(--bad); font-weight:800">Listed</span>' : '<span style="color:var(--good); font-weight:800">Not listed</span>';
  }

  function domPolicyBadge(v){
    const st = (v || '').toString().toLowerCase();
    if(st === 'pass') return '<span style="color:var(--good); font-weight:800">PASS</span>';
    if(st === 'missing') return '<span style="color:var(--warn); font-weight:800">MISSING</span>';
    if(st === 'unknown_selector') return '<span style="color:var(--warn); font-weight:800">UNKNOWN SELECTOR</span>';
    return '<span style="color:var(--warn); font-weight:800">UNKNOWN</span>';
  }

  function renderDomainsTables(){
    const qv = (document.getElementById('domQ')?.value || '').trim().toLowerCase();
    const safeBody = document.getElementById('domTblSafe');
    const safeTotals = document.getElementById('domSafeTotals');

    if(!_domCache || !_domCache.ok){
      if(safeBody) safeBody.innerHTML = `<tr><td colspan="9" class="muted">—</td></tr>`;
      if(safeTotals) safeTotals.textContent = '—';
      return;
    }

    const safe = _domCache.safe || {};
    if(safeTotals){
      safeTotals.textContent = `${safe.total_emails || 0} emails · ${safe.unique_domains || 0} domains · invalid=${safe.invalid_emails || 0}`;
    }
    function safeRows(items){
      const arr = Array.isArray(items) ? items : [];
      const out = [];
      for(const it of arr){
        const dom = (it.domain || '').toString();
        if(qv && !dom.toLowerCase().includes(qv)) continue;
        const mxHosts = (it.mx_hosts || []).slice(0,4).join(', ');
        const ips = (it.mail_ips || []).join(', ');
        out.push(
          `<tr>`+
            `<td><code>${escHtml(dom)}</code></td>`+
            `<td style="font-weight:800">${Number(it.count || 0)}</td>`+
            `<td>${domStatusBadge(it.mx_status)}</td>`+
            `<td class="muted">${escHtml(mxHosts || '—')}</td>`+
            `<td class="muted">${escHtml(ips || '—')}</td>`+
            `<td>${domListedBadge(!!(it.listed ?? it.any_listed))}</td>`+
            `<td>${domPolicyBadge((it.spf || {}).status)}</td>`+
            `<td>${domPolicyBadge((it.dkim || {}).status)}</td>`+
            `<td>${domPolicyBadge((it.dmarc || {}).status)}</td>`+
          `</tr>`
        );
      }
      return out.join('') || `<tr><td colspan="9" class="muted">No results.</td></tr>`;
    }

    if(safeBody) safeBody.innerHTML = safeRows(safe.domains);
  }

  async function refreshDomainsStats(){
    const btn = document.getElementById('btnDomains');
    const status = document.getElementById('domStatus');

    if(btn) btn.disabled = true;
    if(status) status.textContent = 'Loading...';

    try{
      const r = await fetch(`/api/campaign/${CAMPAIGN_ID}/domains_stats`);
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.ok){
        _domCache = j;
        if(status) status.textContent = `OK · ${new Date().toLocaleTimeString()}`;
        renderDomainsTables();
        toast('Save Domains', 'Updated safe domains.', 'good');
      } else {
        const msg = (j && (j.error || j.detail)) ? (j.error || j.detail) : ('HTTP ' + r.status);
        if(status) status.textContent = 'Failed';
        toast('Save Domains failed', msg, 'bad');
      }
    }catch(e){
      if(status) status.textContent = 'Failed';
      toast('Domains stats failed', (e?.toString?.() || 'Unknown error'), 'bad');
    }finally{
      if(btn) btn.disabled = false;
    }
  }

  const domBtn = document.getElementById('btnDomains');
  if(domBtn){ domBtn.addEventListener('click', refreshDomainsStats); }
  const domQ = document.getElementById('domQ');
  if(domQ){ domQ.addEventListener('input', renderDomainsTables); }

  // auto-load safe domains stats once
  refreshDomainsStats();

  // Range value UI
  const scoreEl = document.getElementById('score_range');
  const scoreVal = document.getElementById('score_range_val');
  if(scoreEl && scoreVal){
    const sync = () => { scoreVal.textContent = Number(scoreEl.value).toFixed(1); };
    sync();
    scoreEl.addEventListener('input', sync);
  }
"""

# ---------------------------------------------------------------------------
# Fake data seed
# ---------------------------------------------------------------------------
NOW = datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


DASHBOARD_DATA = {
    "app_name": "Shivamini Frontend Sandbox",
    "campaign": {
        "id": "cmp-demo-001",
        "name": "Ramadan Promo · Demo Campaign",
        "status": "running",
        "owner": "demo@shivamini.local",
        "created_at": iso(NOW - timedelta(days=4, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=3)),
    },
    "kpis": [
        {"label": "Total Recipients", "value": "48,250", "tone": "neutral", "hint": "Loaded from fake campaign audience."},
        {"label": "Delivered", "value": "41,932", "tone": "good", "hint": "Simulated delivered outcomes."},
        {"label": "Deferred", "value": "2,104", "tone": "warn", "hint": "Temporary soft deferrals."},
        {"label": "Bounced", "value": "1,188", "tone": "bad", "hint": "Hard/soft bounce sample total."},
        {"label": "Complaints", "value": "67", "tone": "bad", "hint": "Complaint placeholder metric."},
        {"label": "Spam Score", "value": "2.6 / 10", "tone": "good", "hint": "Fake preflight result."},
        {"label": "Blacklist Health", "value": "2 listed", "tone": "warn", "hint": "Demo DNSBL result."},
        {"label": "Live Queue", "value": "3,842", "tone": "accent", "hint": "Simulated PMTA queue count."},
    ],
    "progress": {
        "overall": 86,
        "domain": 79,
        "chunks": 68,
        "warmup": 91,
    },
    "alerts": [
        {"title": "Adaptive throttle active", "body": "Yahoo lane was slowed down after repeated 4xx responses.", "tone": "warn"},
        {"title": "Bridge connected", "body": "Accounting bridge last synced 22 seconds ago.", "tone": "good"},
        {"title": "Two sender domains listed", "body": "mail-demo.net appears in a fake DNSBL sample.", "tone": "bad"},
    ],
    "ops_snapshot": [
        {"label": "Active operators", "value": "4", "tone": "accent", "hint": "Fake dashboard staffing info for the current shift."},
        {"label": "Bridge poll", "value": "5s", "tone": "good", "hint": "Preview-only bridge polling interval."},
        {"label": "Warmup profile", "value": "Tier B", "tone": "warn", "hint": "Demo sender warmup cohort for this campaign."},
        {"label": "Inbox seed tests", "value": "18/20", "tone": "good", "hint": "Sample seed inbox placement result."},
    ],
    "dashboard_notes": [
        {"title": "Shift owner", "body": "Maya (deliverability) is monitoring Gmail and Outlook lanes for this demo job.", "tone": "accent"},
        {"title": "Next milestone", "body": "The board switches to reconciliation mode after the live queue drops below 1,000 recipients.", "tone": "good"},
        {"title": "Demo caveat", "body": "All numbers on this dashboard are fake placeholders for frontend preview only.", "tone": "warn"},
    ],
    "preflight": {
        "spam_score": 2.6,
        "spam_limit": 4.0,
        "backend": "SpamAssassin (fake)",
        "smtp_host": "pmta.demo.internal",
        "sender_domains": [
            {"domain": "brand-alpha.com", "ips": ["198.51.100.21", "198.51.100.22"], "status": "Not listed", "spam_score": 2.1},
            {"domain": "brand-beta.net", "ips": ["203.0.113.80"], "status": "Listed", "spam_score": 4.4},
            {"domain": "offers-demo.org", "ips": ["203.0.113.110"], "status": "Not listed", "spam_score": 3.0},
        ],
    },
    "excel_info": {
        "file_name": "ramadan-demo-recipients.xlsx",
        "sheet_name": "Audience_Master",
        "rows_total": "48,250",
        "validated_rows": "47,901",
        "suppressed_rows": "349",
        "columns": [
            {"name": "email", "description": "Primary recipient email used to build the fake send queue."},
            {"name": "first_name", "description": "Used with [NAME] and personalization previews inside the HTML body."},
            {"name": "segment", "description": "Maps each row to a campaign slice such as VIP, warm, or re-engagement."},
            {"name": "sender_hint", "description": "Optional sender-domain hint used by the routing preview in Mini Shiva."},
        ],
        "checks": [
            "Accepts .xlsx uploads with one audience sheet or multiple segment sheets.",
            "Normalizes headers automatically before fake preview mapping.",
            "Flags duplicate emails, missing domains, and suppressed rows before send.",
            "Exports a cleaned CSV snapshot for operators to review before starting jobs.",
        ],
    },
    "message_form": {
        "smtp_host": "pmta.demo.internal",
        "smtp_port": 2525,
        "smtp_security": "starttls",
        "smtp_user": "mailer-demo",
        "smtp_timeout": 25,
        "ssh_host": "ops.demo.internal",
        "ssh_port": 22,
        "ssh_user": "pmtaops",
        "ssh_timeout": 8,
        "from_name": "Shivamini Team\nOffers Robot",
        "from_email": "hello@brand-alpha.com\ninfo@brand-beta.net",
        "subject": "Your dashboard demo is ready\nLast chance to review the sandbox",
        "body_format": "html",
        "reply_to": "support@brand-alpha.com",
        "score_range": 4.0,
        "body": "<h1>Hello [NAME]</h1><p>This is a fake preview body for the Shivamini frontend skeleton.</p>",
        "urls_list": "https://brand-alpha.com/demo\nhttps://brand-beta.net/offer",
        "src_list": "https://picsum.photos/seed/shivamini-1/600/240\nhttps://picsum.photos/seed/shivamini-2/600/240",
        "recipients": "amira@example.com\nomar@example.com\nlayla@example.com",
        "maillist_safe": "amira@example.com\nlayla@example.com",
        "delay_s": 0.2,
        "max_rcpt": 50000,
        "chunk_size": 250,
        "thread_workers": 8,
        "sleep_chunks": 1.5,
    },
}

CAMPAIGNS = [
    {
        "id": "cmp-demo-001",
        "name": "Ramadan Promo · Demo Campaign",
        "created_at": iso(NOW - timedelta(days=4, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=3)),
        "jobs": 5,
        "status": "running",
    },
    {
        "id": "cmp-demo-002",
        "name": "Eid Launch · Sample Campaign",
        "created_at": iso(NOW - timedelta(days=10)),
        "updated_at": iso(NOW - timedelta(hours=4)),
        "jobs": 2,
        "status": "paused",
    },
    {
        "id": "cmp-demo-003",
        "name": "Winback Flow · Skeleton",
        "created_at": iso(NOW - timedelta(days=18)),
        "updated_at": iso(NOW - timedelta(days=1, hours=6)),
        "jobs": 9,
        "status": "done",
    },
]

JOBS = [
    {
        "id": "job-240301-a",
        "campaign_id": "cmp-demo-001",
        "status": "running",
        "bridge_mode": "counts",
        "provider": "gmail",
        "risk": "deliverability_high",
        "created_at": iso(NOW - timedelta(hours=7)),
        "updated_at": iso(NOW - timedelta(seconds=30)),
        "sent": 22144,
        "failed": 824,
        "delivered": 21400,
        "deferred": 612,
        "complained": 18,
        "queued": 3842,
        "progress": 84,
        "top_domains": ["gmail.com", "yahoo.com", "outlook.com"],
    },
    {
        "id": "job-240301-b",
        "campaign_id": "cmp-demo-001",
        "status": "backoff",
        "bridge_mode": "legacy",
        "provider": "yahoo",
        "risk": "stale",
        "created_at": iso(NOW - timedelta(days=1, hours=2)),
        "updated_at": iso(NOW - timedelta(minutes=18)),
        "sent": 14488,
        "failed": 1350,
        "delivered": 13002,
        "deferred": 904,
        "complained": 22,
        "queued": 910,
        "progress": 63,
        "top_domains": ["yahoo.com", "aol.com", "icloud.com"],
    },
    {
        "id": "job-240301-c",
        "campaign_id": "cmp-demo-002",
        "status": "paused",
        "bridge_mode": "counts",
        "provider": "outlook",
        "risk": "internal_degraded",
        "created_at": iso(NOW - timedelta(days=2)),
        "updated_at": iso(NOW - timedelta(hours=2, minutes=12)),
        "sent": 6014,
        "failed": 388,
        "delivered": 5701,
        "deferred": 211,
        "complained": 8,
        "queued": 220,
        "progress": 47,
        "top_domains": ["hotmail.com", "outlook.com", "live.com"],
    },
]

JOB_DETAIL = {
    "job_id": "job-240301-a",
    "status": "running",
    "campaign_id": "cmp-demo-001",
    "totals": {"total": 48250, "sent": 42990, "failed": 1188, "skipped": 903, "invalid": 211},
    "domain_state": [
        {"domain": "gmail.com", "planned": 22000, "sent": 19750, "failed": 411, "pct": 92},
        {"domain": "yahoo.com", "planned": 9800, "sent": 7210, "failed": 502, "pct": 78},
        {"domain": "outlook.com", "planned": 8700, "sent": 7440, "failed": 190, "pct": 87},
        {"domain": "icloud.com", "planned": 4200, "sent": 3590, "failed": 85, "pct": 88},
    ],
    "chunks": [
        {"chunk": 188, "status": "running", "size": 250, "sender": "hello@brand-alpha.com", "spam": 2.2, "blacklist": "clean", "attempt": 1, "next_retry": "—"},
        {"chunk": 187, "status": "backoff", "size": 250, "sender": "info@brand-beta.net", "spam": 4.4, "blacklist": "listed", "attempt": 2, "next_retry": "00:02:20"},
        {"chunk": 186, "status": "done", "size": 250, "sender": "hello@brand-alpha.com", "spam": 2.0, "blacklist": "clean", "attempt": 1, "next_retry": "—"},
    ],
    "recent_results": [
        {"ts": iso(NOW - timedelta(minutes=1)), "email": "mona@gmail.com", "ok": True, "detail": "250 2.0.0 Accepted"},
        {"ts": iso(NOW - timedelta(minutes=2)), "email": "saad@yahoo.com", "ok": False, "detail": "421 4.7.0 Temporarily deferred"},
        {"ts": iso(NOW - timedelta(minutes=3)), "email": "nour@outlook.com", "ok": True, "detail": "250 2.6.0 Queued"},
        {"ts": iso(NOW - timedelta(minutes=4)), "email": "huda@icloud.com", "ok": False, "detail": "550 5.1.1 User unknown"},
    ],
    "logs": [
        "[INFO] Chunk 188 started on gmail lane.",
        "[WARN] Yahoo provider triggered adaptive slow mode.",
        "[INFO] Accounting bridge synced 782 events.",
        "[INFO] Preview-only dashboard using fake data.",
    ],
    "telemetry": {
        "mode": "v2 parallel sender lanes",
        "parallel_lanes": [
            {"lane": "lane-1", "sender": "hello@brand-alpha.com", "provider": "gmail.com", "state": "running", "processed": 8400, "success": 8160, "temp_fail": 166, "hard_fail": 74, "workers": 6},
            {"lane": "lane-2", "sender": "info@brand-beta.net", "provider": "yahoo.com", "state": "backoff", "processed": 5220, "success": 4488, "temp_fail": 601, "hard_fail": 131, "workers": 3},
            {"lane": "lane-3", "sender": "promo@offers-demo.org", "provider": "outlook.com", "state": "running", "processed": 6310, "success": 6122, "temp_fail": 110, "hard_fail": 78, "workers": 4},
        ],
    },
}

CONFIG_GROUPS = [
    {"group": "SMTP", "items": [
        {"key": "SHIVA_HOST", "value": "0.0.0.0", "type": "str", "source": "ui", "restart": True, "desc": "Flask bind host"},
        {"key": "SHIVA_PORT", "value": "5001", "type": "int", "source": "ui", "restart": True, "desc": "Flask bind port"},
        {"key": "SPAMCHECK_BACKEND", "value": "spamd", "type": "choice", "source": "env", "restart": False, "desc": "Spam score backend"},
    ]},
    {"group": "PMTA", "items": [
        {"key": "PMTA_QUEUE_BACKOFF", "value": "1", "type": "bool", "source": "ui", "restart": False, "desc": "Enable queue-based backoff"},
        {"key": "PMTA_PRESSURE_CONTROL", "value": "1", "type": "bool", "source": "default", "restart": False, "desc": "Enable pressure monitoring"},
        {"key": "PMTA_LIVE_POLL_S", "value": "5", "type": "int", "source": "ui", "restart": False, "desc": "Refresh interval for fake live stats"},
    ]},
    {"group": "Scheduler", "items": [
        {"key": "SHIVA_SCHEDULER_MODE", "value": "v2", "type": "choice", "source": "ui", "restart": False, "desc": "Fake scheduler mode"},
        {"key": "SHIVA_MAX_PARALLEL_LANES", "value": "8", "type": "int", "source": "ui", "restart": False, "desc": "Max parallel lanes"},
        {"key": "SHIVA_RESOURCE_GOVERNOR", "value": "1", "type": "bool", "source": "default", "restart": False, "desc": "Resource governor status"},
    ]},
]

DOMAINS_DATA = {
    "recipient_domains": [
        {"domain": "gmail.com", "emails": 22000, "mx": "mx", "mx_hosts": ["gmail-smtp-in.l.google.com"], "ips": ["74.125.27.26"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "yahoo.com", "emails": 9800, "mx": "mx", "mx_hosts": ["mta5.am0.yahoodns.net"], "ips": ["67.195.204.77"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "outlook.com", "emails": 8700, "mx": "mx", "mx_hosts": ["outlook-com.olc.protection.outlook.com"], "ips": ["104.47.14.33"], "listed": False, "spf": "pass", "dkim": "missing", "dmarc": "pass"},
    ],
    "sender_domains": [
        {"domain": "brand-alpha.com", "emails": 2, "mx": "mx", "mx_hosts": ["mx1.brand-alpha.com"], "ips": ["198.51.100.21", "198.51.100.22"], "listed": False, "spf": "pass", "dkim": "pass", "dmarc": "pass"},
        {"domain": "brand-beta.net", "emails": 1, "mx": "a_fallback", "mx_hosts": ["fallback.brand-beta.net"], "ips": ["203.0.113.80"], "listed": True, "spf": "pass", "dkim": "missing", "dmarc": "pass"},
        {"domain": "offers-demo.org", "emails": 1, "mx": "mx", "mx_hosts": ["mail.offers-demo.org"], "ips": ["203.0.113.110"], "listed": False, "spf": "pass", "dkim": "unknown_selector", "dmarc": "pass"},
    ],
}

JOBS_NAV_ITEMS = [
    {"label": "Overview", "href": "#job-overview"},
    {"label": "PMTA Live", "href": "#job-pmta-live"},
    {"label": "Outcomes", "href": "#job-outcomes"},
    {"label": "Providers", "href": "#job-providers"},
    {"label": "Chunk preflight", "href": "#job-chunk-preflight"},
]

JOBS_SHOWCASE_HTML = r"""
<div class="job" id="job-overview" data-jobid="83b5cd63007e" data-created="2026-03-22T10:19:10Z">
  <div class="jobTop">
    <div>
      <div class="titleRow">
        <div style="font-weight:900">Job <code>83b5cd63007e</code></div>
        <div class="pill bad" data-k="status">Status: error</div>
        <div class="pill" data-k="speed">0 epm</div>
        <div class="pill" data-k="eta">ETA —</div>
      </div>
      <div class="triageRow">
        <div class="triageBadge" data-k="badgeMode"><span class="badgeLabel">—</span><span class="tip" data-tip="Bridge mode not available yet for this job.">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeFreshness"><span class="badgeLabel">—</span><span class="tip" data-tip="Freshness signal: how recent accounting or legacy ingestion updates are for this job.">ⓘ</span></div>
        <div class="triageBadge good" data-k="badgeHealth"><span class="badgeLabel">OK (0)</span><span class="tip" data-tip="Internal health checks are clean (no bridge/runtime failure counters).">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeRisk"><span class="badgeLabel">RISK —</span><span class="tip" data-tip="Deliverability risk derived from bounce, complaint, and deferred rates.">ⓘ</span></div>
        <div class="triageBadge bridgeConnBadge bad" data-k="badgeBridgeConn" title="Bridge↔Shiva disconnected"><span class="statusDot bad" aria-hidden="true"></span><span>Bridge↔Shiva disconnected</span><span class="tip" data-tip="Real-time bridge transport status between PMTA accounting bridge and Shiva receiver. Current endpoint is not available yet.">ⓘ</span></div>
        <div class="triageBadge" data-k="badgeIntegrity" style="display:none"><span class="badgeLabel">INTEGRITY</span><span class="tip" data-tip="Data integrity counters are clean.">ⓘ</span></div>
      </div>
      <div class="mini">Created: <span class="muted">2026-03-22T10:19:10Z</span></div>
      <div class="mini" data-k="alerts">Quick issues: ❌ abandoned chunks</div>
    </div>

    <div class="nav jobActionNav" style="margin-top:0">
      <a class="btn secondary" href="/job/83b5cd63007e">Open</a>
      <button class="btn secondary" type="button" data-action="pause" disabled>⏸ Pause</button>
      <button class="btn secondary" type="button" data-action="resume" disabled>▶ Resume</button>
      <button class="btn danger" type="button" data-action="stop" disabled>⛔ Stop</button>
      <button class="btn danger" type="button" data-action="delete">🗑 Delete</button>
    </div>
  </div>

  <div class="kpiWrap">
    <div class="kpiRow">
      <div class="kpiCell kpi-sent"><div class="k">Sent</div><div class="v"><span data-k="sent">0</span></div></div>
      <div class="kpiCell"><div class="k">Pending</div><div class="v"><span data-k="pending">0</span><span class="kpiWarn" data-k="pendingWarn" style="display:none" title="Pending was clamped to 0 because Sent is lower than PMTA outcomes.">⚠</span></div></div>
      <div class="kpiCell kpi-del"><div class="k">Del</div><div class="v"><span data-k="delivered">0</span></div></div>
      <div class="kpiCell kpi-bnc"><div class="k">Bnc</div><div class="v"><span data-k="bounced">0</span></div></div>
      <div class="kpiCell kpi-def"><div class="k">Def</div><div class="v"><span data-k="deferred">0</span></div></div>
      <div class="kpiCell kpi-cmp"><div class="k">Cmp</div><div class="v"><span data-k="complained">0</span></div></div>
    </div>
    <div class="ratesRow">
      <div class="rateCell"><div class="k">Bounce %</div><div class="v" data-k="rateBounce">—</div></div>
      <div class="rateCell"><div class="k">Complaint %</div><div class="v" data-k="rateComplaint">—</div></div>
      <div class="rateCell"><div class="k">Deferred %</div><div class="v" data-k="rateDeferred">—</div></div>
    </div>

    <div class="panel" id="job-pmta-live" style="margin-top:10px;">
      <h4>PMTA Live Panel</h4>
      <div class="pmtaLive" data-k="pmtaLine">
        <div class="pmtaGrid">
          <div class="pmtaBox"><div class="pmtaTitle"><span>Spool</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Total recipients/messages currently held by PMTA spool.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Queue</span><span class="tag good">rcpt</span></div><div class="pmtaHint">Recipients/messages still queued to be delivered.</div><div class="pmtaRow"><span class="pmtaKey">RCPT</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">MSG</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Connections</span></div><div class="pmtaHint">Live SMTP sessions used for inbound/outbound traffic.</div><div class="pmtaRow"><span class="pmtaKey">SMTP In</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">SMTP Out</span><span class="pmtaVal good pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Total</span><span class="pmtaVal good">—</span></div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last minute</span></div><div class="pmtaHint">Recent PMTA throughput over the last 60 seconds.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / minute</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Last hour</span></div><div class="pmtaHint">Rolling traffic totals for the previous 60 minutes.</div><div class="pmtaRow"><span class="pmtaKey">In</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaRow"><span class="pmtaKey">Out</span><span class="pmtaVal warn pmtaBig">—</span></div><div class="pmtaSub">traffic recipients / hour</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Top queues</span></div><div class="pmtaHint">Queues with the highest recipient backlog and latest queue errors.</div><div class="pmtaSub">0=0</div></div>
          <div class="pmtaBox"><div class="pmtaTitle"><span>Time</span></div><div class="pmtaHint">Timestamp of the latest PMTA snapshot used for this panel.</div><div class="pmtaSub">2026-03-22T10:19:41Z</div></div>
        </div>
      </div>
      <div class="mini" style="margin-top:6px" data-k="pmtaNote">Note: <b>sent</b> = accepted by PMTA (client-side). Delivery may still be queued/deferred.</div>
      <div class="chunkMeta" style="margin-top:6px" data-k="pmtaDiag"><span class="chunkMetaPill">Diag: —</span></div>
      <div class="mini" style="margin-top:8px"><b>Error summary</b></div>
      <div class="mini errorSummaryBox" data-k="pmtaErrorSummary" style="display: none;"></div>
    </div>

    <details class="qualityMini">
      <summary>Quality</summary>
      <div class="qualityLine">Final-fail: <span data-k="failed">0</span> · Skipped: <span data-k="skipped">0</span> · Invalid: <span data-k="invalid">0</span> · Total: <span data-k="total">1</span></div>
    </details>
  </div>

  <div class="bars">
    <div class="panel">
      <h4>Progress</h4>
      <div class="mini" data-k="progressText">Send progress: 0% (0/1)</div>
      <div class="bar"><div data-k="barSend" style="width: 0%;"></div></div>
      <div class="mini" style="margin-top:8px" data-k="chunksText">Chunks: 1/1 done · backoff_events=0 · abandoned=1</div>
      <div class="mini" data-k="attemptsText" style="display:none">—</div>
      <div class="bar"><div data-k="barChunks" style="width: 100%;"></div></div>
      <div class="mini" style="margin-top:8px" data-k="domainsText">Domains: 0% (0/1)</div>
      <div class="bar"><div data-k="barDomains" style="width: 0%;"></div></div>
    </div>
  </div>

  <div class="quickIssues" data-k="quickIssues">Quick issues: ❌ abandoned chunks</div>

  <details class="more" open>
    <summary>More details</summary>
    <div class="moreBlock twoCol">
      <div class="panel">
        <h4>Current chunk</h4>
        <div class="mini">Current send settings + top active domains in this running chunk.</div>
        <div class="mini" data-k="chunkLine"><div class="mini">—</div></div>
        <div class="mini" data-k="chunkDomains"><div class="mini chunkNote chunkNoteDomains">🔥 Top active domains: —</div></div>
      </div>
      <div class="panel">
        <h4>Backoff</h4>
        <div class="mini">Latest retry event when PMTA/provider pressure slows delivery.</div>
        <div class="mini" data-k="backoffLine">—</div>
      </div>
    </div>

    <div class="panel moreBlock" id="job-outcomes">
      <h4>Outcomes (PMTA accounting)</h4>
      <div class="outcomesWrap" data-k="outcomes">
        <div class="outcomesGrid">
          <div class="outChip del"><span class="k">Delivered</span><span class="v">0</span></div>
          <div class="outChip bnc"><span class="k">Bounced</span><span class="v">0</span></div>
          <div class="outChip def"><span class="k">Deferred</span><span class="v">0</span></div>
          <div class="outChip cmp"><span class="k">Complained</span><span class="v">0</span></div>
        </div>
        <div class="outMeta">Pending (sent - final outcomes): <b>0</b> · PMTA queue now: <b>0</b></div>
        <div class="outMeta">Last accounting update: —</div>
      </div>
      <div class="outTrend" data-k="outcomeTrend">Trend · —</div>
    </div>

    <div class="moreGrid moreBlock">
      <div class="panel" id="job-providers">
        <h4 data-k="domainsPanelTitle">Top providers</h4>
        <div class="mini" data-k="topDomains">Gmail: <b>0</b> · Yahoo: <b>0</b> · Outlook: <b>0</b> · iCloud: <b>0</b> · Other: <b>1</b></div>
        <div class="mini" style="margin-top: 10px; display: none;"><b>Domain progress (bars)</b></div>
        <div data-k="topDomainsBars"><div style="margin-top:10px"><div class="mini"><b>Gmail</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Yahoo</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Outlook</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>iCloud</b> · 0</div><div class="smallBar"><div style="width:0%"></div></div></div><div style="margin-top:10px"><div class="mini"><b>Other</b> · 1</div><div class="smallBar"><div style="width:100%"></div></div></div></div>
      </div>

      <div class="panel">
        <h4 class="sopHeader">📌 System / Provider / Integrity</h4>

        <div class="sopBlock">
          <div class="sopLabel system">🖥️ System / Internal</div>
          <div class="sopLine" data-k="systemSummary">🔗 Bridge failures: <b>0</b> · ⏱️ Last bridge success: <b>0m ago</b> · ⚙️ Runtime internal errors: <b>0</b> · 💾 DB write failures: <b>0</b></div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="systemDetails">—</div>
          </details>
        </div>

        <div class="sopBlock">
          <div class="sopLabel provider">📬 Provider / Deliverability</div>
          <div class="sopLine" data-k="providerSummary">✅ Delivered: <b>0</b> (—) · ⏳ Deferred: <b>0</b> (—) · ❌ Bounced: <b>0</b> (—) · 📢 Complained: <b>0</b> (—)</div>
          <div class="sopLine" style="margin-top:6px" data-k="providerBreakdown">🌐 Provider/domain breakdown: —</div>
          <div class="sopLine" style="margin-top:6px" data-k="providerReasons">🧠 Top reason buckets: —</div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="providerDetails">—</div>
          </details>
        </div>

        <div class="sopBlock">
          <div class="sopLabel integrity">🗂️ Data Integrity / Mapping</div>
          <div class="sopLine" data-k="integritySummary">♻️ duplicates_dropped: <b>0</b> · 🔎 job_not_found: <b>0</b> · 🧾 missing_fields: <b>0</b> · 💽 db_write_failures: <b>0</b></div>
          <details class="errorFold">
            <summary>View details</summary>
            <div class="mini" style="margin-top:8px" data-k="integrityDetails">—</div>
          </details>
        </div>

        <div class="legacyDiagnosticsBox">
          <div class="legacyDiagnosticsTitle">📄 Legacy quality + errors (unchanged data)</div>
          <div class="legacySectionLabel">📊 Quality counters</div>
          <div class="mini legacyDataLine" data-k="counters">safe_total=0 · safe_invalid=0 · invalid_filtered=0 · skipped=0 · backoff_events=0 · abandoned_chunks=1 · paused=no · stop_requested=no</div>
          <div class="legacySectionLabel">🚨 Error type</div>
          <div class="mini legacyDataLine" data-k="errorTypes">—</div>
          <div class="legacySectionLabel">⚠️ Error summary</div>
          <div class="mini legacyDataLine" data-k="lastErrors">—</div>
          <div class="mini legacyDataLine" data-k="lastErrors2">—</div>
          <div class="mini legacyDataLine" data-k="internalErrors">—</div>
        </div>
        <div class="bridgeSnapshotBox">
          <div class="legacySectionLabel" style="margin-top:0">🌉 Data source: Bridge snapshot</div>
          <div class="mini legacyDataLine" style="margin-top:8px" data-k="bridgeReceiver">Data source: <b>Bridge snapshot</b><br>Last poll success: <b>2026-03-22T11:55:02Z (2m ago)</b><br>Last accounting update: <b>—</b></div>
        </div>
      </div>
    </div>

    <div class="panel" id="job-chunk-preflight" style="margin-top:10px">
      <h4>Chunk preflight</h4>
      <div class="mini" style="margin-top:6px"><b>Active / Live chunk</b></div>
      <div style="overflow:auto; margin-top:8px">
        <table>
          <thead>
            <tr>
              <th>Chunk</th>
              <th>Status</th>
              <th>Size</th>
              <th>Sender mail</th>
              <th>Receiver domain</th>
              <th>Spam</th>
              <th>Blacklist</th>
            </tr>
          </thead>
          <tbody data-k="chunkLive"><tr><td colspan="7" class="mini">No active chunk right now.</td></tr></tbody>
        </table>
      </div>

      <div class="mini" style="margin-top:10px"><b>History chunk (last 12)</b></div>
      <div style="overflow:auto; margin-top:8px">
        <table>
          <thead>
            <tr>
              <th>Chunk</th>
              <th>Status</th>
              <th>Size</th>
              <th>Sender mail</th>
              <th>Receiver domain</th>
              <th>Spam</th>
              <th>Blacklist</th>
              <th>Attempt</th>
              <th>Next retry</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody data-k="chunkHist"><tr><td>2</td><td>abandoned</td><td>1</td><td title="welcome@101crossroadsstudio.com">welcome@101crossroadsstudio.co…</td><td>srv1.mail-tester.com</td><td>-1.90</td><td title="domain:101crossroadsstudio.com=&gt;dbl.spamhaus.org">domain:101crossroadsstudio.com…</td><td><b>0</b></td><td><span title="">—</span></td><td title="preflight_blocked: blacklist">preflight_blocked: blacklist</td></tr></tbody>
        </table>
      </div>
    </div>
  </details>
</div>
"""


def build_live_snapshot() -> dict:
    snapshot = copy.deepcopy(DASHBOARD_DATA)
    jitter = random.randint(-80, 80)
    queue_jitter = random.randint(-120, 120)
    snapshot["kpis"] = copy.deepcopy(DASHBOARD_DATA["kpis"])
    snapshot["kpis"][1]["value"] = f"{41932 + jitter:,}"
    snapshot["kpis"][3]["value"] = f"{1188 + abs(jitter // 4):,}"
    snapshot["kpis"][7]["value"] = f"{max(3200, 3842 + queue_jitter):,}"
    snapshot["progress"] = {
        "overall": max(10, min(100, DASHBOARD_DATA["progress"]["overall"] + random.randint(-2, 2))),
        "domain": max(10, min(100, DASHBOARD_DATA["progress"]["domain"] + random.randint(-2, 2))),
        "chunks": max(10, min(100, DASHBOARD_DATA["progress"]["chunks"] + random.randint(-3, 3))),
        "warmup": max(10, min(100, DASHBOARD_DATA["progress"]["warmup"] + random.randint(-1, 1))),
    }
    snapshot["campaign"]["updated_at"] = iso(datetime.now(timezone.utc))
    return snapshot


PAGE = r"""
<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{{ title }}</title>
  <style>
    :root{
      --bg1:#0b1020; --bg2:#0a1a2b;
      --card: rgba(255,255,255,.08);
      --card2: rgba(255,255,255,.06);
      --border: rgba(255,255,255,.14);
      --text: rgba(255,255,255,.92);
      --muted: rgba(255,255,255,.65);
      --good: #35e49a;
      --bad: #ff5e73;
      --warn: #ffc14d;
      --accent:#7aa7ff;
      --shadow: 0 20px 60px rgba(0,0,0,.35);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: system-ui, -apple-system, "Segoe UI", Tahoma, Arial;
      color: var(--text);
      background:
        radial-gradient(1000px 700px at 80% 20%, rgba(122,167,255,.22), transparent 60%),
        radial-gradient(900px 700px at 20% 30%, rgba(53,228,154,.16), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      min-height:100vh;
    }
    a{color:var(--accent); text-decoration:none}
    .shell{display:grid; grid-template-columns:280px 1fr; min-height:100vh}
    .sidebar{padding:22px 18px; border-right:1px solid rgba(255,255,255,.08); background:rgba(5,10,18,.35); position:sticky; top:0; height:100vh}
    .brand{font-weight:900; font-size:22px; letter-spacing:.3px}
    .brandSub{margin-top:8px; color:var(--muted); font-size:13px; line-height:1.6}
    .menu{display:flex; flex-direction:column; gap:10px; margin-top:22px}
    .menu a{display:flex; align-items:center; gap:10px; padding:12px 14px; border-radius:14px; border:1px solid rgba(255,255,255,.1); background:rgba(255,255,255,.04)}
    .menu a.active{background:rgba(122,167,255,.18); border-color:rgba(122,167,255,.35); font-weight:800}
    .sidebarCard{margin-top:18px; padding:14px; border-radius:16px; border:1px solid var(--border); background:linear-gradient(180deg,var(--card),var(--card2)); box-shadow:var(--shadow)}
    .content{padding:28px 18px 28px 24px}
    .wrap{max-width: 1100px; margin: 0 auto;}
    .top{
      display:flex; gap:14px; align-items:flex-start; justify-content:space-between;
      flex-wrap:wrap; margin-bottom: 18px;
    }
    h1,.title{ margin:0; font-size: 22px; letter-spacing: .2px; }
    .title{font-size:28px}
    .sub,.subtitle{
      margin-top:6px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      max-width: 980px;
    }
    .subtitle{font-size:14px; line-height:1.7}
    .badge,.pill,.tag{
      display:inline-flex; align-items:center; gap:8px;
      padding: 10px 12px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 999px;
      box-shadow: var(--shadow);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      text-decoration:none;
    }
    .tag{padding:5px 10px; font-weight:800; box-shadow:none; background:rgba(255,255,255,.06)}
    .tag.good,.tone-good{color:var(--good); border-color:rgba(53,228,154,.35)}
    .tag.bad,.tone-bad{color:var(--bad); border-color:rgba(255,94,115,.35)}
    .tag.warn,.tone-warn{color:var(--warn); border-color:rgba(255,193,77,.35)}
    .tag.accent,.tone-accent{color:var(--accent); border-color:rgba(122,167,255,.35)}
    .topActions{ display:flex; flex-direction:column; gap:10px; align-items:flex-end; }
    .topLinks{ display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
    .grid{ display:grid; gap: 14px; }
    .grid.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
    .grid.two{grid-template-columns:1.2fr .8fr}
    .grid.three{grid-template-columns:repeat(3,minmax(0,1fr))}
    .grid.send-layout{grid-template-columns: minmax(0, 1.05fr) minmax(340px, .95fr)}
    .stack{ display:flex; flex-direction:column; gap:14px; }
    .card{
      background: linear-gradient(180deg, var(--card), var(--card2));
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 16px;
      backdrop-filter: blur(10px);
    }
    .card h2,.card h3,.card h4{ margin:0 0 10px; font-size: 16px; color: rgba(255,255,255,.88); }
    label{ display:block; margin: 10px 0 6px; color: var(--muted); font-size: 12px; font-weight:700; }
    input, select, textarea{
      width:100%;
      padding: 11px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,.16);
      background: rgba(0,0,0,.18);
      color: var(--text);
      outline: none;
      font: inherit;
    }
    input::placeholder, textarea::placeholder{color: rgba(255,255,255,.35)}
    textarea{min-height: 130px; resize: vertical}
    .row,.split,.telemetryRow{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .hint,.alert,.laneBox,.emptyState,.check{
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.06);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.6;
    }
    .alert{margin-bottom:10px}
    .alert.good{ border-color: rgba(53,228,154,.35); background: rgba(53,228,154,.08); }
    .alert.warn{ border-color: rgba(255,193,77,.35); background: rgba(255,193,77,.08); }
    .alert.bad{ border-color: rgba(255,94,115,.35); background: rgba(255,94,115,.08); }
    .alert.accent{ border-color: rgba(122,167,255,.35); background: rgba(122,167,255,.08); }
    .actions{display:flex; gap:10px; align-items:center; justify-content:flex-start; flex-wrap: wrap; margin-top: 14px;}
    .btn, button{
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(122,167,255,.18);
      color: var(--text);
      padding: 12px 14px;
      border-radius: 14px;
      cursor:pointer;
      font-weight: 600;
      letter-spacing:.2px;
      font:inherit;
    }
    .btn:hover, button:hover{filter: brightness(1.06)}
    .btn.secondary, button.secondary{ background: rgba(255,255,255,.08); }
    .btn:disabled, button:disabled{ opacity:.55; cursor:not-allowed; }
    .check{display:flex; gap: 8px; align-items:flex-start; margin-top: 12px; background: rgba(0,0,0,.12)}
    .check input{width:auto; margin-top: 2px;}
    .foot,.footerNote{ margin-top: 16px; color: rgba(255,255,255,.45); font-size: 12px; line-height: 1.7; }
    .mini,.muted{ font-size: 12px; color: var(--muted); margin-top: 8px; }
    code{background:rgba(255,255,255,.08); padding:2px 6px; border-radius:8px;}
    .smallBar,.bar{height:10px; border-radius:999px; background:rgba(255,255,255,.10); border:1px solid rgba(255,255,255,.12); overflow:hidden}
    .smallBar > div,.bar > div{height:100%; width:0%; background: linear-gradient(90deg, var(--accent), rgba(53,228,154,.75));}
    .nav{display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin:8px 0 14px;}
    .nav a, .nav button{display:inline-flex; align-items:center; gap:8px; padding:8px 10px; border:1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); border-radius: 12px; text-decoration:none;}
    .nav a:hover{filter:brightness(1.06)}
    .nav a.primary{ background: rgba(122,167,255,.14); font-weight:800; }
    table{width:100%; border-collapse:collapse; font-size: 12px;}
    th,td{padding:8px; border-bottom:1px solid rgba(255,255,255,.10); text-align:left; vertical-align:top}
    .statsList{display:grid; gap:10px}
    .kpi .label{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.4px}
    .kpi .value{font-size:28px; font-weight:900; margin-top:6px}
    .progressLine{margin-top:10px}
    .field{margin-bottom:12px}
    .toast-wrap{ position: fixed; right: 16px; bottom: 16px; z-index: 9999; display:flex; flex-direction:column; gap:10px; }
    .toast{ min-width: 280px; max-width: 420px; background: rgba(0,0,0,.55); border: 1px solid rgba(255,255,255,.18); box-shadow: 0 18px 55px rgba(0,0,0,.35); backdrop-filter: blur(10px); border-radius: 14px; padding: 12px 14px; color: rgba(255,255,255,.92); font-size: 13px; line-height: 1.5; animation: pop .18s ease-out; }
    @keyframes pop{ from{ transform: translateY(6px); opacity: .2; } to{ transform: translateY(0); opacity: 1; } }
    .toast .t{font-weight:800; margin-bottom:4px}
    .toast.good{ border-color: rgba(53,228,154,.35); }
    .toast.bad{ border-color: rgba(255,94,115,.35); }
    .toast.warn{ border-color: rgba(255,193,77,.35); }
    .inline-status{ margin-top: 10px; padding: 10px 12px; border-radius: 14px; border: 1px solid rgba(255,255,255,.14); background: rgba(0,0,0,.12); color: var(--muted); font-size: 12px; line-height: 1.6; display:none; }
    .inline-status.show{ display:block; }
    .inline-status b{ color: rgba(255,255,255,.88); }
    .sectionNav{display:flex; gap:10px; flex-wrap:wrap; margin:14px 0 18px}
    .sectionNav a{display:inline-flex; align-items:center; gap:8px; padding:10px 12px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.05)}
    .job{padding:18px; border-radius:22px; border:1px solid var(--border); background:linear-gradient(180deg, rgba(9,16,28,.92), rgba(11,24,38,.84)); box-shadow:var(--shadow)}
    .jobTop{display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap}
    .titleRow,.triageRow,.kpiRow,.ratesRow,.outcomesGrid,.pmtaGrid,.moreGrid{display:grid; gap:10px}
    .titleRow{grid-template-columns:repeat(auto-fit,minmax(120px,max-content)); align-items:center}
    .triageRow{grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); margin-top:12px}
    .triageBadge,.chunkMetaPill,.outChip,.pmtaBox,.rateCell,.kpiCell,.sopBlock,.legacyDiagnosticsBox,.bridgeSnapshotBox{border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.05); border-radius:16px}
    .triageBadge{display:flex; align-items:center; gap:8px; padding:10px 12px; color:var(--muted)}
    .triageBadge.good{border-color:rgba(53,228,154,.3); color:var(--good)}
    .triageBadge.bad{border-color:rgba(255,94,115,.3); color:var(--bad)}
    .statusDot{width:10px; height:10px; border-radius:999px; display:inline-block; background:currentColor}
    .badgeLabel{font-weight:700}
    .tip{cursor:help; opacity:.8}
    .jobActionNav{align-self:flex-start}
    .kpiWrap,.bars,.quickIssues,.moreBlock{margin-top:14px}
    .kpiRow{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
    .ratesRow{grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); margin-top:10px}
    .kpiCell,.rateCell,.outChip{padding:12px}
    .kpiCell .k,.rateCell .k,.outChip .k,.pmtaKey,.pmtaHint,.pmtaSub,.sopLine,.legacyDataLine{color:var(--muted); font-size:12px}
    .kpiCell .v,.rateCell .v,.outChip .v{font-size:24px; font-weight:900; margin-top:6px}
    .kpi-del .v,.outChip.del .v,.pmtaVal.good{color:var(--good)}
    .kpi-bnc .v,.outChip.bnc .v,.bridgeConnBadge.bad{color:var(--bad)}
    .kpi-def .v,.outChip.def .v,.pmtaVal.warn{color:var(--warn)}
    .kpi-cmp .v,.outChip.cmp .v{color:#ff97cf}
    .kpi-sent .v{color:var(--accent)}
    .kpiWarn{margin-left:6px; color:var(--warn)}
    .panel{padding:16px; border-radius:18px; border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.04)}
    .pmtaGrid{grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); margin-top:12px}
    .pmtaBox{padding:12px}
    .pmtaTitle{display:flex; justify-content:space-between; gap:8px; align-items:center; font-weight:800}
    .pmtaRow{display:flex; justify-content:space-between; gap:8px; margin-top:10px}
    .pmtaBig{font-size:22px; font-weight:900}
    .qualityMini{margin-top:12px}
    .qualityLine,.outMeta,.outTrend{margin-top:10px; color:var(--muted); font-size:12px}
    .quickIssues{padding:12px 14px; border:1px solid rgba(255,94,115,.25); background:rgba(255,94,115,.08); border-radius:14px; color:#ffd8df}
    .more summary,.errorFold summary,.qualityMini summary{cursor:pointer; font-weight:800}
    .twoCol{display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px}
    .outcomesGrid{grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); margin-top:12px}
    .moreGrid{grid-template-columns:minmax(260px,.9fr) minmax(320px,1.1fr)}
    .sopHeader{margin-bottom:12px}
    .sopBlock,.legacyDiagnosticsBox,.bridgeSnapshotBox{padding:12px; margin-top:12px}
    .sopLabel,.legacyDiagnosticsTitle,.legacySectionLabel{font-weight:800; margin-bottom:8px}
    .sopLabel.system{color:var(--accent)}
    .sopLabel.provider{color:var(--warn)}
    .sopLabel.integrity{color:var(--good)}
    .errorSummaryBox{padding:10px 12px; border-radius:14px; border:1px dashed rgba(255,255,255,.14)}
    @media (max-width: 1200px){ .grid.kpis{grid-template-columns:repeat(2,minmax(0,1fr))} .grid.two,.grid.send-layout,.split,.telemetryRow,.twoCol,.moreGrid{grid-template-columns:1fr} }
    @media (max-width: 920px){ .shell{grid-template-columns:1fr} .sidebar{position:relative; height:auto; border-right:0; border-bottom:1px solid rgba(255,255,255,.08)} .grid.three{grid-template-columns:1fr} }
    @media (max-width: 520px){ .row{grid-template-columns: 1fr;} .topActions{ align-items:stretch; width:100%; } .topLinks{ justify-content:flex-start; } .content{padding:18px 14px 24px} .sectionNav a{width:100%; justify-content:center} }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">Shivamini</div>
      <div class="brandSub">Unified single-file Flask frontend sandbox with the Shiva Mini Sand styling applied across dashboard, jobs, job details, config, domains, and send surfaces.</div>
      <nav class="menu">
        <a href="{{ url_for('dashboard') }}" class="{% if page == 'dashboard' %}active{% endif %}">📊 Dashboard</a>
        <a href="{{ url_for('campaigns_page') }}" class="{% if page == 'campaigns' %}active{% endif %}">📌 Campaigns</a>
        <a href="{{ url_for('send_page') }}" class="{% if page == 'send' %}active{% endif %}">✉️ Send</a>
        <a href="{{ url_for('jobs_page') }}" class="{% if page == 'jobs' %}active{% endif %}">📄 Jobs</a>
        <a href="{{ url_for('job_page', job_id='job-240301-a') }}" class="{% if page == 'job' %}active{% endif %}">🧩 Job Detail</a>
        <a href="{{ url_for('config_page') }}" class="{% if page == 'config' %}active{% endif %}">⚙️ Config</a>
        <a href="{{ url_for('domains_page') }}" class="{% if page == 'domains' %}active{% endif %}">🌐 Domains</a>
      </nav>
      <div class="sidebarCard">
        <div style="font-weight:800">Demo status</div>
        <div class="mini" style="margin-top:8px">Campaign: <code>{{ sidebar_campaign.name }}</code><br>Status: <b>{{ sidebar_campaign.status }}</b><br>Updated: {{ sidebar_campaign.updated_at }}</div>
      </div>
    </aside>
    <main class="content">
      {{ body|safe }}
      <div class="footerNote">All frontend surfaces now inherit the same Shiva Mini Sand dashboard visual language from this single Python file.</div>
    </main>
  </div>
<script>
async function hydrateDashboard(){
  const root = document.getElementById('liveDashboardRoot');
  if(!root) return;
  try{
    const res = await fetch('{{ url_for('api_dashboard') }}');
    const data = await res.json();
    const kpiNodes = root.querySelectorAll('[data-kpi-value]');
    kpiNodes.forEach((node, idx) => {
      if(data.kpis && data.kpis[idx]) node.textContent = data.kpis[idx].value;
    });
    Object.entries(data.progress || {}).forEach(([name, value]) => {
      const bar = root.querySelector(`[data-progress="${name}"]`);
      const text = root.querySelector(`[data-progress-text="${name}"]`);
      if(bar) bar.style.width = value + '%';
      if(text) text.textContent = value + '%';
    });
    const stamp = document.getElementById('liveStamp');
    if(stamp) stamp.textContent = data.campaign.updated_at;
  }catch(err){
    console.warn('Dashboard hydrate failed', err);
  }
}
setInterval(hydrateDashboard, 4000);
hydrateDashboard();
</script>
{{ page_script|safe }}
</body>
</html>
"""


def render(page: str, title: str, body: str, page_script: str = ""):

    return render_template_string(
        PAGE,
        page=page,
        title=title,
        body=body,
        page_script=page_script,
        sidebar_campaign=DASHBOARD_DATA["campaign"],
    )


@app.get("/")
def dashboard():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Dashboard frontend skeleton</h1>
            <div class="subtitle">A full Flask-only mock frontend that mirrors the core dashboard surfaces: overview KPIs, alerts, campaign form, preflight summary, jobs, telemetry, config, and domains — all backed by fake data.</div>
          </div>
          <div class="actions">
            <a class="btn" href="{{ url_for('jobs_page') }}">Open Jobs</a>
            <a class="btn secondary" href="{{ url_for('config_page') }}">Open Config</a>
            <span class="pill">Live fake refresh: <b id="liveStamp">{{ data.campaign.updated_at }}</b></span>
          </div>
        </div>

        <div id="liveDashboardRoot">
          <div class="grid kpis">
            {% for item in data.kpis %}
            <div class="card kpi">
              <div class="label">{{ item.label }}</div>
              <div class="value tone-{{ item.tone if item.tone in ['good','bad','warn','accent'] else 'accent' }}" data-kpi-value>{{ item.value }}</div>
              <div class="mini">{{ item.hint }}</div>
            </div>
            {% endfor %}
          </div>

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Campaign summary</h2>
              <div class="split">
                <div class="statsList">
                  <div><span class="mini">Campaign</span><div><b>{{ data.campaign.name }}</b></div></div>
                  <div><span class="mini">Owner</span><div>{{ data.campaign.owner }}</div></div>
                  <div><span class="mini">Campaign ID</span><div><code>{{ data.campaign.id }}</code></div></div>
                  <div><span class="mini">Status</span><div><span class="tag good">{{ data.campaign.status }}</span></div></div>
                </div>
                <div class="statsList">
                  {% for key, value in data.progress.items() %}
                  <div class="progressLine">
                    <div style="display:flex; justify-content:space-between; gap:8px; margin-bottom:6px">
                      <span style="text-transform:capitalize">{{ key }}</span>
                      <b data-progress-text="{{ key }}">{{ value }}%</b>
                    </div>
                    <div class="bar"><div data-progress="{{ key }}" style="width:{{ value }}%"></div></div>
                  </div>
                  {% endfor %}
                </div>
              </div>
            </div>
            <div class="card">
              <h2>Alerts & notices</h2>
              {% for alert in data.alerts %}
              <div class="alert {{ alert.tone }}">
                <div style="font-weight:800">{{ alert.title }}</div>
                <div class="mini" style="margin-top:6px">{{ alert.body }}</div>
              </div>
              {% endfor %}
            </div>
          </div>

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Excel audience workflow</h2>
              <div class="mini">Mini Shiva now highlights how the Excel import is prepared before operators open the dedicated Send surface.</div>
              <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
                <span class="tag accent">Workbook {{ data.excel_info.file_name }}</span>
                <span class="tag good">Sheet {{ data.excel_info.sheet_name }}</span>
                <span class="tag">Rows {{ data.excel_info.rows_total }}</span>
                <span class="tag good">Validated {{ data.excel_info.validated_rows }}</span>
                <span class="tag warn">Suppressed {{ data.excel_info.suppressed_rows }}</span>
              </div>
              <div class="grid two" style="margin-top:12px">
                <div>
                  <h3 style="margin:0 0 10px">Mapped columns</h3>
                  <table>
                    <thead><tr><th>Column</th><th>Usage</th></tr></thead>
                    <tbody>
                      {% for column in data.excel_info.columns %}
                      <tr>
                        <td><code>{{ column.name }}</code></td>
                        <td>{{ column.description }}</td>
                      </tr>
                      {% endfor %}
                    </tbody>
                  </table>
                </div>
                <div>
                  <h3 style="margin:0 0 10px">Preparation checks</h3>
                  <div class="statsList">
                    {% for item in data.excel_info.checks %}
                    <div class="alert accent" style="margin:0">{{ item }}</div>
                    {% endfor %}
                  </div>
                </div>
              </div>
            </div>
            <div class="card">
              <h2>Preflight summary</h2>
              <div class="mini">SMTP host: <code>{{ data.preflight.smtp_host }}</code> · Backend: {{ data.preflight.backend }}</div>
              <div style="margin-top:10px; display:flex; gap:10px; flex-wrap:wrap">
                <span class="tag good">Spam {{ data.preflight.spam_score }}</span>
                <span class="tag warn">Limit {{ data.preflight.spam_limit }}</span>
                <span class="tag accent">{{ data.preflight.sender_domains|length }} sender domains</span>
              </div>
              <div style="overflow:auto; margin-top:12px">
                <table>
                  <thead><tr><th>Domain</th><th>IPs</th><th>Status</th><th>Spam</th></tr></thead>
                  <tbody>
                    {% for item in data.preflight.sender_domains %}
                    <tr>
                      <td>{{ item.domain }}</td>
                      <td>{{ item.ips|join(', ') }}</td>
                      <td><span class="tag {{ 'bad' if item.status == 'Listed' else 'good' }}">{{ item.status }}</span></td>
                      <td>{{ item.spam_score }}</td>
                    </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div class="grid two" style="margin-top:14px">
            <div class="card">
              <h2>Operations snapshot</h2>
              <div class="grid two" style="margin-top:12px">
                {% for item in data.ops_snapshot %}
                <div class="alert {{ item.tone }}" style="margin:0">
                  <div style="font-weight:800">{{ item.label }}</div>
                  <div style="font-size:22px; font-weight:900; margin-top:8px">{{ item.value }}</div>
                  <div class="mini">{{ item.hint }}</div>
                </div>
                {% endfor %}
              </div>
            </div>
            <div class="card">
              <h2>Dashboard fake notes</h2>
              <div class="statsList" style="margin-top:12px">
                {% for note in data.dashboard_notes %}
                <div class="alert {{ note.tone }}" style="margin:0">
                  <div style="font-weight:800">{{ note.title }}</div>
                  <div class="mini" style="margin-top:6px">{{ note.body }}</div>
                </div>
                {% endfor %}
              </div>
            </div>
          </div>
        </div>
        """,
        data=DASHBOARD_DATA,
    )
    return render("dashboard", "Shivamini Dashboard", body)


@app.get("/send")
def send_page():
    body = render_template_string(SEND_PAGE_BODY, campaign_ts=NOW.strftime("%Y-%m-%d %H:%M:%S"))
    page_script = "<script>\n" + SEND_PAGE_SCRIPT + "\n</script>"
    return render("send", "Shivamini Send", body, page_script=page_script)


@app.get("/campaigns")
def campaigns_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Campaigns</h1>
            <div class="subtitle">Frontend-only sample listing for saved campaigns, states, and quick open actions.</div>
          </div>
          <div class="actions">
            <button>➕ New Campaign</button>
            <button class="secondary">🧨 Wipe Demo Data</button>
          </div>
        </div>
        <div class="grid">
          {% for campaign in campaigns %}
          <div class="card">
            <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap">
              <div>
                <h3>{{ campaign.name }}</h3>
                <div class="mini">ID: <code>{{ campaign.id }}</code> · Created: {{ campaign.created_at }}</div>
              </div>
              <div class="tag {{ 'good' if campaign.status == 'running' else ('warn' if campaign.status == 'paused' else 'accent') }}">{{ campaign.status }}</div>
            </div>
            <div class="mini" style="margin-top:8px">Updated: {{ campaign.updated_at }} · Jobs: {{ campaign.jobs }}</div>
            <div class="actions" style="margin-top:12px">
              <a class="btn" href="{{ url_for('dashboard') }}">Open</a>
              <button class="secondary">Rename</button>
              <button class="secondary">Duplicate</button>
              <button class="secondary">Delete</button>
            </div>
          </div>
          {% endfor %}
        </div>
        """,
        campaigns=CAMPAIGNS,
    )
    return render("campaigns", "Shivamini Campaigns", body)


@app.get("/jobs")
def jobs_page():
    return Response(JOBS_PAGE_HTML, mimetype="text/html")


@app.get("/job/<job_id>")
def job_page(job_id: str):
    detail = copy.deepcopy(JOB_DETAIL)
    detail["job_id"] = job_id
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Job detail · <code>{{ detail.job_id }}</code></h1>
            <div class="subtitle">Detailed fake job view: totals, domains, chunk state, recent results, logs, and lane telemetry.</div>
          </div>
          <div class="actions">
            <a class="btn" href="{{ url_for('jobs_page') }}">← Back to jobs</a>
            <button class="secondary">📥 Delivered CSV</button>
            <button class="secondary">⏳ Queue CSV</button>
            <button class="secondary">🚫 Failed CSV</button>
          </div>
        </div>
        <div class="grid two">
          <div class="card">
            <h2>Totals</h2>
            <div class="grid three">
              {% for key, value in detail.totals.items() %}
              <div>
                <div class="mini">{{ key|replace('_', ' ')|title }}</div>
                <div style="font-size:24px; font-weight:900">{{ '{:,}'.format(value) }}</div>
              </div>
              {% endfor %}
            </div>
          </div>
          <div class="card">
            <h2>Scheduler telemetry</h2>
            <div class="mini">Mode: <b>{{ detail.telemetry.mode }}</b></div>
            <div class="telemetryRow" style="margin-top:10px">
              {% for lane in detail.telemetry.parallel_lanes %}
              <div class="laneBox">
                <div style="font-weight:800">{{ lane.lane }}</div>
                <div class="mini">{{ lane.sender }} → {{ lane.provider }}</div>
                <div style="margin-top:8px"><span class="tag {{ 'warn' if lane.state == 'backoff' else 'good' }}">{{ lane.state }}</span></div>
                <div class="mini" style="margin-top:8px">Processed {{ lane.processed }} · Success {{ lane.success }} · Temp {{ lane.temp_fail }} · Hard {{ lane.hard_fail }} · Workers {{ lane.workers }}</div>
              </div>
              {% endfor %}
            </div>
          </div>
        </div>

        <div class="grid two" style="margin-top:14px">
          <div class="card">
            <h2>Domain state</h2>
            <table>
              <thead><tr><th>Domain</th><th>Planned</th><th>Sent</th><th>Failed</th><th>Progress</th></tr></thead>
              <tbody>
                {% for row in detail.domain_state %}
                <tr>
                  <td>{{ row.domain }}</td>
                  <td>{{ row.planned }}</td>
                  <td>{{ row.sent }}</td>
                  <td>{{ row.failed }}</td>
                  <td style="min-width:180px"><div class="bar"><div style="width:{{ row.pct }}%"></div></div><div class="mini">{{ row.pct }}%</div></td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Chunk state & backoff</h2>
            <table>
              <thead><tr><th>Chunk</th><th>Status</th><th>Size</th><th>Sender</th><th>Spam</th><th>BL</th><th>Attempt</th><th>Next retry</th></tr></thead>
              <tbody>
                {% for row in detail.chunks %}
                <tr>
                  <td>{{ row.chunk }}</td>
                  <td><span class="tag {{ 'warn' if row.status == 'backoff' else ('good' if row.status == 'running' else 'accent') }}">{{ row.status }}</span></td>
                  <td>{{ row.size }}</td>
                  <td>{{ row.sender }}</td>
                  <td>{{ row.spam }}</td>
                  <td>{{ row.blacklist }}</td>
                  <td>{{ row.attempt }}</td>
                  <td>{{ row.next_retry }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>

        <div class="grid two" style="margin-top:14px">
          <div class="card">
            <h2>Recent results</h2>
            <table>
              <thead><tr><th>Time</th><th>Email</th><th>OK</th><th>Detail</th></tr></thead>
              <tbody>
                {% for item in detail.recent_results %}
                <tr>
                  <td>{{ item.ts }}</td>
                  <td>{{ item.email }}</td>
                  <td><span class="tag {{ 'good' if item.ok else 'bad' }}">{{ 'YES' if item.ok else 'NO' }}</span></td>
                  <td>{{ item.detail }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Recent logs</h2>
            <div style="white-space:pre-wrap; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:13px">{{ detail.logs|join('\n') }}</div>
          </div>
        </div>
        """,
        detail=detail,
    )
    return render("job", f"Shivamini Job {job_id}", body)


@app.get("/config")
def config_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Config surface</h1>
            <div class="subtitle">Static config table intended for frontend extraction and future replacement with your real settings API.</div>
          </div>
          <div class="actions">
            <button>💾 Save all</button>
            <button class="secondary">🔄 Reload</button>
          </div>
        </div>
        <div class="grid">
          {% for group in groups %}
          <div class="card">
            <h2>{{ group.group }}</h2>
            <table>
              <thead><tr><th>Key</th><th>Value</th><th>Type</th><th>Source</th><th>Restart</th><th>Description</th></tr></thead>
              <tbody>
                {% for item in group["items"] %}
                <tr>
                  <td><code>{{ item.key }}</code></td>
                  <td>{{ item.value }}</td>
                  <td>{{ item.type }}</td>
                  <td><span class="tag {{ 'good' if item.source == 'ui' else ('warn' if item.source == 'env' else 'accent') }}">{{ item.source }}</span></td>
                  <td>{{ 'yes' if item.restart else 'no' }}</td>
                  <td>{{ item.desc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          {% endfor %}
        </div>
        """,
        groups=CONFIG_GROUPS,
    )
    return render("config", "Shivamini Config", body)


@app.get("/domains")
def domains_page():
    body = render_template_string(
        """
        <div class="top">
          <div>
            <h1 class="title">Domains health</h1>
            <div class="subtitle">Recipient and sender domain tables with fake MX/SPF/DKIM/DMARC/blacklist states for visual frontend testing.</div>
          </div>
          <div class="actions">
            <button>🌐 Refresh</button>
            <button class="secondary">🔎 Search</button>
          </div>
        </div>
        <div class="grid two">
          <div class="card">
            <h2>Recipient domains</h2>
            <table>
              <thead><tr><th>Domain</th><th>Emails</th><th>MX</th><th>Hosts</th><th>IPs</th><th>Listed</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
              <tbody>
                {% for item in data.recipient_domains %}
                <tr>
                  <td>{{ item.domain }}</td>
                  <td>{{ item.emails }}</td>
                  <td>{{ item.mx }}</td>
                  <td>{{ item.mx_hosts|join(', ') }}</td>
                  <td>{{ item.ips|join(', ') }}</td>
                  <td><span class="tag {{ 'bad' if item.listed else 'good' }}">{{ 'listed' if item.listed else 'clean' }}</span></td>
                  <td>{{ item.spf }}</td>
                  <td>{{ item.dkim }}</td>
                  <td>{{ item.dmarc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          <div class="card">
            <h2>Sender domains</h2>
            <table>
              <thead><tr><th>Domain</th><th>Emails</th><th>MX</th><th>Hosts</th><th>IPs</th><th>Listed</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
              <tbody>
                {% for item in data.sender_domains %}
                <tr>
                  <td>{{ item.domain }}</td>
                  <td>{{ item.emails }}</td>
                  <td>{{ item.mx }}</td>
                  <td>{{ item.mx_hosts|join(', ') }}</td>
                  <td>{{ item.ips|join(', ') }}</td>
                  <td><span class="tag {{ 'bad' if item.listed else 'good' }}">{{ 'listed' if item.listed else 'clean' }}</span></td>
                  <td>{{ item.spf }}</td>
                  <td>{{ item.dkim }}</td>
                  <td>{{ item.dmarc }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
        """,
        data=DOMAINS_DATA,
    )
    return render("domains", "Shivamini Domains", body)


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(build_live_snapshot())


@app.get("/api/jobs")
def api_jobs():
    return jsonify({"jobs": JOBS})


@app.get("/api/job/<job_id>")
def api_job(job_id: str):
    detail = copy.deepcopy(JOB_DETAIL)
    detail["job_id"] = job_id
    return jsonify(detail)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5099, debug=True)
