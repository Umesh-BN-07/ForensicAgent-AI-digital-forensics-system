import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from PIL import Image

from api import analyze_folder, open_report, check_backend


# -------------------- Theme --------------------
BG = "#09090B"
SIDEBAR = "#18181B"
PANEL = "#27272A"
CARD = "#18181B"
CARD_HOVER = "#27272A"
BORDER = "#3F3F46"
TEXT = "#FAFAFA"
MUTED = "#A1A1AA"
BLUE = "#3B82F6"
CYAN = "#06B6D4"
GREEN = "#10B981"
YELLOW = "#F59E0B"
ORANGE = "#F97316"
RED = "#EF4444"
PURPLE = "#8B5CF6"


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def risk_color(risk):
    return {
        "LOW": GREEN,
        "MEDIUM": YELLOW,
        "HIGH": ORANGE,
        "CRITICAL": RED
    }.get(str(risk).upper(), BLUE)


class MetricCard(ctk.CTkFrame):
    def __init__(self, master, title, value="—", subtitle="", color=BLUE):
        super().__init__(master, fg_color=CARD, corner_radius=18,
                         border_width=1, border_color=BORDER)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text=title.upper(), text_color=MUTED,
                     font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, sticky="w", padx=18, pady=(15, 3))
        self.value_label = ctk.CTkLabel(
            self, text=value, text_color=color,
            font=("Segoe UI", 32, "bold"))
        self.value_label.grid(row=1, column=0, sticky="w", padx=18, pady=2)
        self.sub_label = ctk.CTkLabel(
            self, text=subtitle, text_color=MUTED,
            font=("Segoe UI", 12))
        self.sub_label.grid(row=2, column=0, sticky="w", padx=18, pady=(2, 15))

    def update(self, value, subtitle=None, color=None):
        self.value_label.configure(text=value)
        if subtitle is not None:
            self.sub_label.configure(text=subtitle)
        if color:
            self.value_label.configure(text_color=color)


class ThreatGauge(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=CARD, corner_radius=18,
                         border_width=1, border_color=BORDER)
        self.canvas = tk.Canvas(self, width=250, height=230,
                                bg=CARD, highlightthickness=0)
        self.canvas.pack(padx=10, pady=8)

    def draw(self, score):
        self.canvas.delete("all")
        score = max(0, min(100, int(score)))
        cx, cy, r = 125, 112, 82
        
        # Background Track
        self.canvas.create_arc(cx-r, cy-r, cx+r, cy+r,
                               start=135, extent=-270,
                               style="arc", outline=PANEL, width=18)
                               
        extent = -270 * score / 100
        color = RED if score >= 80 else ORANGE if score >= 60 else YELLOW if score >= 30 else GREEN
        
        # Glow layers (simulated)
        self.canvas.create_arc(cx-r, cy-r, cx+r, cy+r,
                               start=135, extent=extent,
                               style="arc", outline=color, width=22, stipple="gray25")
        
        # Main Arc
        self.canvas.create_arc(cx-r, cy-r, cx+r, cy+r,
                               start=135, extent=extent,
                               style="arc", outline=color, width=14)
                               
        self.canvas.create_text(cx, cy-5, text=str(score),
                                fill=TEXT, font=("Segoe UI", 48, "bold"))
        self.canvas.create_text(cx, cy+34, text="THREAT SCORE",
                                fill=BLUE, font=("Segoe UI", 12, "bold"))
                                
        self.canvas.create_text(35, 202, text="0", fill=MUTED, font=("Segoe UI", 11))
        self.canvas.create_text(215, 202, text="100", fill=MUTED, font=("Segoe UI", 11))


class Timeline(ctk.CTkScrollableFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=CARD, corner_radius=18,
                         border_width=1, border_color=BORDER)

    def render(self, events):
        for child in self.winfo_children():
            child.destroy()

        if not events:
            ctk.CTkLabel(self, text="No timeline events available.",
                         text_color=MUTED).pack(pady=30)
            return

        for i, event in enumerate(events):
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=4)
            row.grid_columnconfigure(1, weight=1)

            dot_color = RED if event.get("event") in {
                "LOGIN_FAILED", "LOG_DELETE", "FILE_DOWNLOAD"
            } else BLUE

            dot = ctk.CTkLabel(row, text="●", text_color=dot_color,
                               font=("Segoe UI", 16))
            dot.grid(row=0, column=0, padx=(5, 12), sticky="n")

            body = ctk.CTkFrame(row, fg_color="#0F1A2B", corner_radius=12)
            body.grid(row=0, column=1, sticky="ew")
            body.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(body, text=event.get("timestamp", "—"),
                         text_color=CYAN,
                         font=("Consolas", 10, "bold")).grid(
                row=0, column=0, padx=12, pady=(9, 1), sticky="w")
            ctk.CTkLabel(body, text=event.get("event", "UNKNOWN"),
                         text_color=TEXT,
                         font=("Segoe UI", 12, "bold")).grid(
                row=1, column=0, padx=12, pady=1, sticky="w")
            user = event.get("user") or "Unknown user"
            details = event.get("details") or event.get("raw") or ""
            ctk.CTkLabel(body, text=f"{user}  •  {details}",
                         text_color=MUTED,
                         font=("Segoe UI", 10),
                         wraplength=800, justify="left").grid(
                row=2, column=0, padx=12, pady=(1, 9), sticky="w")


class ForensicApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ForensicAgent • AI Digital Forensics")
        self.geometry("1450x900")
        self.minsize(1180, 760)
        self.configure(fg_color=BG)

        self.selected_folder = None
        self.current_analysis = None
        self.current_report = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.build_sidebar()
        self.build_main()

        self.show_dashboard()
        self.set_status("Ready • Select evidence to begin")

    # ---------- Sidebar ----------
    def build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0,
                                    fg_color=SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(8, weight=1)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, padx=24, pady=(35, 40), sticky="ew")

        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        if os.path.exists(logo_path):
            logo_img = ctk.CTkImage(light_image=Image.open(logo_path),
                                    dark_image=Image.open(logo_path),
                                    size=(100, 100))
            icon = ctk.CTkLabel(brand, text="", image=logo_img)
        else:
            icon = ctk.CTkLabel(brand, text="✦", text_color=CYAN,
                                font=("Segoe UI", 34, "bold"))
        icon.pack(side="left", padx=(0, 12))

        labels = ctk.CTkFrame(brand, fg_color="transparent")
        labels.pack(side="left")
        ctk.CTkLabel(labels, text="FORENSIC", text_color=TEXT,
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(labels, text="AI INVESTIGATION", text_color=BLUE,
                     font=("Segoe UI", 10, "bold")).pack(anchor="w")

        self.nav_buttons = {}
        nav = [
            ("⌂", "Dashboard", self.show_dashboard),
            ("⇧", "Evidence", self.show_evidence),
            ("◉", "Investigation", self.show_investigation),
            ("▣", "Reports", self.show_reports),
            ("ⓘ", "About", self.show_about),
        ]

        for idx, (ico, name, command) in enumerate(nav, start=1):
            btn = ctk.CTkButton(
                self.sidebar, text=f"  {ico}   {name}",
                anchor="w", height=44, corner_radius=10,
                fg_color="transparent", hover_color=CARD_HOVER,
                text_color=MUTED, font=("Segoe UI", 13, "bold"),
                command=command)
            btn.grid(row=idx, column=0, padx=15, pady=4, sticky="ew")
            self.nav_buttons[name] = btn

        status = ctk.CTkFrame(self.sidebar, fg_color="#0B1526",
                              corner_radius=14, border_width=1,
                              border_color=BORDER)
        status.grid(row=9, column=0, padx=15, pady=18, sticky="ew")
        ctk.CTkLabel(status, text="●  SYSTEM ONLINE", text_color=GREEN,
                     font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
        self.backend_label = ctk.CTkLabel(
            status, text="Backend: checking...",
            text_color=MUTED, font=("Segoe UI", 9))
        self.backend_label.pack(anchor="w", padx=12, pady=(0, 10))

    # ---------- Main ----------
    def build_main(self):
        self.main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self.main, height=80, fg_color=BG)
        top.grid(row=0, column=0, sticky="ew", padx=36, pady=(25, 10))
        top.grid_columnconfigure(0, weight=1)

        self.page_title = ctk.CTkLabel(
            top, text="Investigation Dashboard",
            text_color=TEXT, font=("Segoe UI", 28, "bold"))
        self.page_title.grid(row=0, column=0, sticky="w")

        self.status_pill = ctk.CTkLabel(
            top, text="●  READY", text_color=GREEN,
            fg_color="#10251B", corner_radius=12,
            padx=12, pady=6, font=("Segoe UI", 10, "bold"))
        self.status_pill.grid(row=0, column=1, padx=10)

        self.content = ctk.CTkFrame(self.main, fg_color=BG)
        self.content.grid(row=1, column=0, sticky="nsew", padx=28, pady=(0, 20))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    def clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def set_page(self, title, active=None):
        self.page_title.configure(text=title)
        for name, btn in self.nav_buttons.items():
            if name == active:
                btn.configure(fg_color="#15304A", text_color=TEXT)
            else:
                btn.configure(fg_color="transparent", text_color=MUTED)

    def set_status(self, text, color=GREEN):
        self.status_pill.configure(text=f"●  {text.upper()}", text_color=color)

    # ---------- Dashboard ----------
    def show_dashboard(self):
        self.clear_content()
        self.set_page("Investigation Dashboard", "Dashboard")

        frame = ctk.CTkScrollableFrame(self.content, fg_color=BG)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure((0, 1, 2), weight=1)

        welcome = ctk.CTkFrame(frame, fg_color=PANEL, corner_radius=24,
                               border_width=1, border_color=BORDER)
        welcome.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 24))
        welcome.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(welcome, text="AI-POWERED DIGITAL FORENSICS",
                     text_color=CYAN,
                     font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, padx=30, pady=(25, 4), sticky="w")
        ctk.CTkLabel(welcome, text="Investigate evidence. Correlate events. Find the story.",
                     text_color=TEXT,
                     font=("Segoe UI", 26, "bold")).grid(
            row=1, column=0, padx=30, pady=4, sticky="w")
        ctk.CTkLabel(welcome,
                     text="Select a complete evidence folder and let Evidence, Log, ML, NLP, Correlation and Report agents work together automatically.",
                     text_color=MUTED, font=("Segoe UI", 14)).grid(
            row=2, column=0, padx=30, pady=(4, 25), sticky="w")

        ctk.CTkButton(
            welcome, text="＋  Start New Investigation",
            height=46, corner_radius=14, fg_color=BLUE,
            hover_color="#2563EB", text_color="#FAFAFA",
            font=("Segoe UI", 13, "bold"),
            command=self.show_evidence).grid(
            row=1, column=1, rowspan=2, padx=30, pady=25)

        # Current metrics
        score = 0
        risk = "NO CASE"
        ml = "—"
        events = 0
        if self.current_analysis:
            log = self.current_analysis.get("log_analysis", {})
            score = log.get("threat_score", 0)
            risk = log.get("risk_level", "—")
            ml = log.get("ml_analysis", {}).get("prediction", "—")
            events = log.get("total_events", 0)

        MetricCard(frame, "Threat Score", str(score),
                   "Overall forensic risk", risk_color(risk)).grid(
            row=1, column=0, sticky="ew", padx=(0, 12), pady=12)
        MetricCard(frame, "Risk Level", risk,
                   "Current investigation", risk_color(risk)).grid(
            row=1, column=1, sticky="ew", padx=12, pady=12)
        MetricCard(frame, "ML Detection", ml,
                   f"{events} events analyzed", PURPLE).grid(
            row=1, column=2, sticky="ew", padx=(12, 0), pady=12)

        # Recent case panel
        panel = ctk.CTkFrame(frame, fg_color=CARD, corner_radius=22,
                             border_width=1, border_color=BORDER)
        panel.grid(row=2, column=0, columnspan=3, sticky="ew", pady=24)
        ctk.CTkLabel(panel, text="CURRENT CASE",
                     text_color=MUTED, font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=24, pady=(22, 6))
        file_name = os.path.basename(os.path.normpath(self.selected_folder)) if self.selected_folder else "No evidence folder selected"
        ctk.CTkLabel(panel, text=file_name, text_color=TEXT,
                     font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=24)
        ctk.CTkLabel(panel,
                     text="SHA-256 integrity verification • Rule-based detection • Isolation Forest • Correlation",
                     text_color=MUTED, font=("Segoe UI", 13)).pack(
            anchor="w", padx=24, pady=(6, 22))

    # ---------- Evidence ----------
    def show_evidence(self):
        self.clear_content()
        self.set_page("Evidence Collection", "Evidence")

        frame = ctk.CTkScrollableFrame(self.content, fg_color=BG)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Collect a Complete Evidence Folder",
            text_color=TEXT,
            font=("Segoe UI", 28, "bold")
        ).grid(row=0, column=0, sticky="w", pady=(10, 4))

        ctk.CTkLabel(
            frame,
            text=(
                "Select a folder. ForensicAgent recursively collects every file, "
                "calculates SHA-256 hashes, analyzes supported logs/text, correlates "
                "findings and automatically generates one forensic report."
            ),
            text_color=MUTED,
            font=("Segoe UI", 12),
            wraplength=950,
            justify="left"
        ).grid(row=1, column=0, sticky="w", pady=(0, 20))

        drop = ctk.CTkFrame(
            frame,
            fg_color=PANEL,
            corner_radius=20,
            border_width=2,
            border_color="#1D3B57",
            height=250
        )
        drop.grid(row=2, column=0, sticky="ew", pady=10)
        drop.grid_propagate(False)

        ctk.CTkLabel(
            drop, text="▣", text_color=CYAN,
            font=("Segoe UI", 48, "bold")
        ).pack(pady=(25, 0))

        self.file_label = ctk.CTkLabel(
            drop,
            text="No evidence folder selected",
            text_color=MUTED,
            font=("Segoe UI", 13),
            wraplength=900
        )
        self.file_label.pack(pady=8)

        ctk.CTkButton(
            drop,
            text="Browse Evidence Folder",
            width=230,
            height=42,
            corner_radius=12,
            fg_color=BLUE,
            text_color="#06111D",
            font=("Segoe UI", 12, "bold"),
            command=self.choose_folder
        ).pack(pady=10)

        self.analyze_button = ctk.CTkButton(
            frame,
            text="▶  Start Autonomous Investigation",
            height=50,
            corner_radius=12,
            fg_color="#16A34A",
            hover_color="#15803D",
            font=("Segoe UI", 13, "bold"),
            command=self.start_analysis
        )
        self.analyze_button.grid(row=3, column=0, sticky="ew", pady=12)

        self.progress = ctk.CTkProgressBar(
            frame, height=8, progress_color=CYAN, fg_color="#172337"
        )
        self.progress.grid(row=4, column=0, sticky="ew", pady=(2, 4))
        self.progress.set(0)

        self.activity = ctk.CTkLabel(
            frame,
            text="Ready to collect the complete evidence folder.",
            text_color=MUTED,
            font=("Segoe UI", 11)
        )
        self.activity.grid(row=5, column=0, sticky="w", pady=(2, 15))

        self.stats_label = ctk.CTkLabel(
            frame,
            text="",
            text_color=CYAN,
            font=("Segoe UI", 11, "bold")
        )
        self.stats_label.grid(row=6, column=0, sticky="w", pady=(0, 10))

        if self.selected_folder:
            self.file_label.configure(
                text=self.selected_folder,
                text_color=TEXT
            )

    def choose_folder(self):
        path = filedialog.askdirectory(
            title="Select Complete Forensic Evidence Folder"
        )
        if path:
            self.selected_folder = path

            file_count = 0
            total_size = 0
            for root, _, files in os.walk(path):
                for filename in files:
                    file_count += 1
                    try:
                        total_size += os.path.getsize(os.path.join(root, filename))
                    except OSError:
                        pass

            size_mb = total_size / (1024 * 1024)
            self.file_label.configure(
                text=path,
                text_color=TEXT
            )
            self.stats_label.configure(
                text=f"Selected: {file_count} files  •  {size_mb:.2f} MB"
            )
            self.set_status("Evidence folder selected", BLUE)

    def start_analysis(self):
        if not self.selected_folder:
            messagebox.showwarning(
                "Evidence Required",
                "Please select an evidence folder first."
            )
            return

        self.analyze_button.configure(
            state="disabled",
            text="Analyzing complete evidence set…"
        )
        self.progress.set(0.05)
        self.activity.configure(
            text="Packaging the complete evidence folder…",
            text_color=CYAN
        )
        self.set_status("Processing folder", YELLOW)

        threading.Thread(
            target=self._folder_analysis_worker,
            daemon=True
        ).start()

    def _folder_analysis_worker(self):
        try:
            self.after(100, lambda: self.progress.set(0.20))
            self.after(100, lambda: self.activity.configure(
                text="Collecting every file and preserving folder structure…"
            ))

            result = analyze_folder(self.selected_folder)

            if not result.get("success"):
                raise RuntimeError(
                    result.get("message", "Folder investigation failed")
                )

            self.after(100, lambda: self.progress.set(0.70))
            self.after(100, lambda: self.activity.configure(
                text="Running forensic agents and correlating evidence…"
            ))

            self.current_analysis = result["analysis"]
            self.current_report = (
                result.get("report")
                or self.current_analysis.get("report")
            )

            self.after(100, lambda: self.progress.set(1.0))
            self.after(150, lambda: self.activity.configure(
                text="Investigation complete • Report generated automatically.",
                text_color=GREEN
            ))
            self.after(200, self.show_investigation)

        except Exception as exc:
            self.after(0, lambda: messagebox.showerror(
                "Investigation Error", str(exc)
            ))
            self.after(0, lambda: self.set_status("Error", RED))
            self.after(0, lambda: self.analyze_button.configure(
                state="normal",
                text="▶  Start Autonomous Investigation"
            ))

    # ---------- Investigation ----------
    def show_investigation(self):
        self.clear_content()
        self.set_page("Investigation Results", "Investigation")

        if not self.current_analysis:
            ctk.CTkLabel(self.content, text="No investigation available.",
                         text_color=MUTED,
                         font=("Segoe UI", 16)).grid(row=0, column=0, pady=80)
            return

        self.set_status("Investigation complete", GREEN)

        frame = ctk.CTkScrollableFrame(self.content, fg_color=BG)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure((0, 1, 2), weight=1)

        log = self.current_analysis.get("log_analysis", {})
        corr = self.current_analysis.get("correlation", {})
        score = int(log.get("threat_score", 0))
        risk = log.get("risk_level", "UNKNOWN")
        ml = log.get("ml_analysis", {})
        events = log.get("events", [])
        findings = log.get("findings", [])
        summary = corr.get("summary", [])
        folder_stats = self.current_analysis.get("statistics", {})

        ctk.CTkLabel(frame, text="Investigation Overview",
                     text_color=GREEN,
                     font=("Segoe UI", 25, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(5, 14))

        ctk.CTkLabel(
            frame,
            text=(
                f"Folder: {self.current_analysis.get('folder_name', 'Evidence')}  •  "
                f"Files: {folder_stats.get('total_files', 0)}  •  "
                f"Events: {folder_stats.get('total_events', 0)}  •  "
                f"Findings: {folder_stats.get('total_findings', 0)}"
            ),
            text_color=MUTED,
            font=("Segoe UI", 11)
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        gauge = ThreatGauge(frame)
        gauge.grid(row=1, column=0, sticky="nsew", padx=(0, 8), pady=5)
        gauge.draw(score)

        MetricCard(frame, "Risk Level", risk, "Forensic classification",
                   risk_color(risk)).grid(
            row=1, column=1, sticky="nsew", padx=8, pady=5)

        MetricCard(frame, "ML Prediction", ml.get("prediction", "—"),
                   f"Confidence: {ml.get('confidence', '—')}",
                   PURPLE).grid(
            row=1, column=2, sticky="nsew", padx=(8, 0), pady=5)

        # Findings
        find_panel = ctk.CTkFrame(frame, fg_color=CARD, corner_radius=18,
                                  border_width=1, border_color=BORDER)
        find_panel.grid(row=2, column=0, columnspan=3, sticky="ew", pady=14)
        ctk.CTkLabel(find_panel, text="⚠  THREAT FINDINGS",
                     text_color=TEXT,
                     font=("Segoe UI", 15, "bold")).pack(
            anchor="w", padx=18, pady=(16, 8))

        if not findings:
            ctk.CTkLabel(find_panel, text="No suspicious findings detected.",
                         text_color=GREEN).pack(anchor="w", padx=18, pady=(0, 16))
        else:
            for item in findings:
                row = ctk.CTkFrame(find_panel, fg_color="#0F1A2B",
                                   corner_radius=10)
                row.pack(fill="x", padx=14, pady=4)
                sev = item.get("severity", "LOW")
                ctk.CTkLabel(row, text=f"●  {sev}",
                             text_color=risk_color(sev),
                             font=("Segoe UI", 10, "bold"),
                             width=90).pack(side="left", padx=12, pady=10)
                ctk.CTkLabel(row, text=item.get("description", "Unknown finding"),
                             text_color=TEXT,
                             font=("Segoe UI", 11)).pack(
                    side="left", padx=4, pady=10)

        # Two-column section
        left = ctk.CTkFrame(frame, fg_color=CARD, corner_radius=18,
                            border_width=1, border_color=BORDER)
        left.grid(row=3, column=0, columnspan=2, sticky="nsew",
                  padx=(0, 8), pady=5)
        ctk.CTkLabel(left, text="◉  ATTACK TIMELINE",
                     text_color=TEXT,
                     font=("Segoe UI", 15, "bold")).pack(
            anchor="w", padx=18, pady=(16, 10))

        timeline = Timeline(left)
        timeline.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        timeline.configure(height=330)
        timeline.render(corr.get("timeline", events))

        right = ctk.CTkFrame(frame, fg_color=CARD, corner_radius=18,
                             border_width=1, border_color=BORDER)
        right.grid(row=3, column=2, sticky="nsew",
                   padx=(8, 0), pady=5)
        ctk.CTkLabel(right, text="✦  AI CONCLUSION",
                     text_color=TEXT,
                     font=("Segoe UI", 15, "bold")).pack(
            anchor="w", padx=18, pady=(16, 10))

        for line in summary:
            ctk.CTkLabel(right, text=f"• {line}",
                         text_color=MUTED,
                         font=("Segoe UI", 11),
                         wraplength=320,
                         justify="left").pack(
                anchor="w", padx=18, pady=6)

        # Bottom buttons
        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.grid(row=4, column=0, columnspan=3, sticky="ew", pady=18)

        ctk.CTkButton(actions, text="⇩  Open PDF Report",
                      height=44, corner_radius=12,
                      fg_color=BLUE, text_color="#06111D",
                      font=("Segoe UI", 12, "bold"),
                      command=self.open_current_report).pack(
            side="left", padx=(0, 10))

        ctk.CTkButton(actions, text="＋  New Investigation",
                      height=44, corner_radius=12,
                      fg_color=CARD, hover_color=CARD_HOVER,
                      border_width=1, border_color=BORDER,
                      command=self.show_evidence).pack(
            side="left")

    def open_current_report(self):
        path = self.current_report
        if not path:
            messagebox.showwarning("Report Not Available",
                                   "No report path was returned by the backend.")
            return
        try:
            open_report(path)
        except Exception as exc:
            messagebox.showerror("Open Report Error", str(exc))

    # ---------- Reports ----------
    def show_reports(self):
        self.clear_content()
        self.set_page("Forensic Reports", "Reports")

        frame = ctk.CTkFrame(self.content, fg_color=BG)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Generated Reports",
                     text_color=TEXT,
                     font=("Segoe UI", 28, "bold")).grid(
            row=0, column=0, sticky="w", pady=(10, 5))
        ctk.CTkLabel(frame,
                     text="Open the latest investigation report generated by ForensicAgent.",
                     text_color=MUTED).grid(
            row=1, column=0, sticky="w", pady=(0, 20))

        card = ctk.CTkFrame(frame, fg_color=CARD, corner_radius=18,
                            border_width=1, border_color=BORDER)
        card.grid(row=2, column=0, sticky="ew")

        if self.current_report:
            ctk.CTkLabel(card, text=os.path.basename(self.current_report),
                         text_color=TEXT,
                         font=("Segoe UI", 14, "bold")).pack(
                anchor="w", padx=20, pady=(18, 4))
            ctk.CTkLabel(card, text=str(self.current_report),
                         text_color=MUTED,
                         wraplength=900).pack(
                anchor="w", padx=20, pady=2)
            ctk.CTkButton(card, text="Open Report", command=self.open_current_report,
                          width=170, height=40).pack(
                anchor="w", padx=20, pady=16)
        else:
            ctk.CTkLabel(card, text="No report generated in this session.",
                         text_color=MUTED).pack(padx=20, pady=30)

    # ---------- About ----------
    def show_about(self):
        self.clear_content()
        self.set_page("About ForensicAgent", "About")

        card = ctk.CTkFrame(self.content, fg_color=PANEL, corner_radius=22,
                            border_width=1, border_color=BORDER)
        card.grid(row=0, column=0, sticky="nsew", padx=30, pady=30)

        ctk.CTkLabel(card, text="◈", text_color=CYAN,
                     font=("Segoe UI", 60, "bold")).pack(pady=(45, 5))
        ctk.CTkLabel(card, text="ForensicAgent",
                     text_color=TEXT,
                     font=("Segoe UI", 32, "bold")).pack()
        ctk.CTkLabel(card, text="AI Agent for Automated Digital Forensics Investigation",
                     text_color=BLUE,
                     font=("Segoe UI", 14, "bold")).pack(pady=5)

        text = (
            "ForensicAgent combines evidence collection, log analysis, "
            "machine-learning anomaly detection, NLP analysis and event "
            "correlation to assist investigators in understanding suspicious activity."
        )
        ctk.CTkLabel(card, text=text, text_color=MUTED,
                     wraplength=800, justify="center",
                     font=("Segoe UI", 13)).pack(pady=25)

        ctk.CTkLabel(card, text="Python  •  Flask  •  CustomTkinter  •  scikit-learn  •  spaCy  •  ReportLab",
                     text_color="#64748B",
                     font=("Segoe UI", 11)).pack(pady=10)


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()
