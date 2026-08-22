import customtkinter as ctk
from tkinter import filedialog, messagebox

from api import upload_file, analyze_log
from components.stat_card import StatCard
from api import open_report
from components.progress_card import ProgressCard


class UploadPage(ctk.CTkFrame):

    def __init__(self, master):

        super().__init__(master)

        self.selected_file = None

        # -----------------------------
        # Title
        # -----------------------------
        title = ctk.CTkLabel(
            self,
            text="Upload Digital Evidence",
            font=("Arial", 28, "bold")
        )

        title.pack(pady=20)

        # -----------------------------
        # Selected File Label
        # -----------------------------
        self.filename_label = ctk.CTkLabel(
            self,
            text="No file selected",
            font=("Arial", 15)
        )

        self.filename_label.pack(pady=10)

        # -----------------------------
        # Browse Button
        # -----------------------------
        browse_btn = ctk.CTkButton(
            self,
            text="Browse Evidence",
            width=220,
            height=45,
            command=self.browse_file
        )

        browse_btn.pack(pady=10)

        # -----------------------------
        # Analyze Button
        # -----------------------------
        analyze_btn = ctk.CTkButton(
            self,
            text="Analyze Evidence",
            width=220,
            height=45,
            command=self.analyze
        )

        analyze_btn.pack(pady=10)

        # -----------------------------
        # Result Box
        # -----------------------------
        self.result_box = ctk.CTkTextbox(
            self,
            width=900,
            height=450
        )

        self.result_box.pack(
            padx=20,
            pady=20,
            fill="both",
            expand=True
        )

        self.result_box.insert(
            "1.0",
            "Upload a log file and click Analyze Evidence..."
        )

    # ==========================================================
    # Browse File
    # ==========================================================

    def browse_file(self):

        filepath = filedialog.askopenfilename(

            filetypes=[
                ("Log Files", "*.log"),
                ("Text Files", "*.txt"),
                ("CSV Files", "*.csv")
            ]
        )

        if filepath:

            self.selected_file = filepath

            self.filename_label.configure(
                text=filepath
            )

    # ==========================================================
    # Analyze
    # ==========================================================

    def analyze(self):

        if not self.selected_file:

            messagebox.showwarning(
                "Warning",
                "Please select a file first."
            )

            return

        try:

            # Upload evidence
            upload = upload_file(
                self.selected_file
            )

            if not upload["success"]:

                messagebox.showerror(
                    "Upload Failed",
                    upload["message"]
                )

                return

            stored_filename = upload["evidence"]["stored_filename"]

            # Analyze log
            result = analyze_log(
                stored_filename
            )

            if not result["success"]:

                messagebox.showerror(
                    "Analysis Failed",
                    "Investigation failed."
                )

                return

            analysis = result["analysis"]

            self.show_dashboard(
                analysis
            )

        except Exception as e:

            messagebox.showerror(
                "Error",
                str(e)
            )

    # ==========================================================
    # Dashboard
    # ==========================================================

    def show_dashboard(self, analysis):

        self.result_box.destroy()

        dashboard = ctk.CTkScrollableFrame(self)

        dashboard.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20
        )

        score = analysis["log_analysis"]["threat_score"]

        progress = ProgressCard(
            dashboard,
            "Threat Score",
            score
        )

        progress.pack(
            pady=15
        )

        # ----------------------------
        # Risk Card
        # ----------------------------

        risk = ctk.CTkFrame(
            dashboard,
            fg_color="#2B2B2B"
        )

        risk.pack(
            fill="x",
            pady=10
        )

        ctk.CTkLabel(
            risk,
            text="Risk Level",
            font=("Arial", 18, "bold")
        ).pack()

        ctk.CTkLabel(
            risk,
            text=analysis["log_analysis"]["risk_level"],
            font=("Arial", 30, "bold"),
            text_color="red"
        ).pack(pady=10)

        # ----------------------------
        # ML Card
        # ----------------------------

        ml = ctk.CTkFrame(
            dashboard,
            fg_color="#2B2B2B"
        )

        ml.pack(
            fill="x",
            pady=10
        )

        prediction = analysis["log_analysis"]["ml_analysis"]

        ctk.CTkLabel(
            ml,
            text="Machine Learning",
            font=("Arial", 18, "bold")
        ).pack()

        ctk.CTkLabel(
            ml,
            text=prediction["prediction"],
            font=("Arial", 24, "bold")
        ).pack()

        ctk.CTkLabel(
            ml,
            text=f"Confidence : {prediction['confidence']}",
            font=("Arial", 16)
        ).pack()

        # ----------------------------
        # Findings
        # ----------------------------

        findings = ctk.CTkTextbox(
            dashboard,
            height=180
        )

        findings.pack(
            fill="x",
            pady=15
        )

        findings.insert(
            "end",
            "THREAT FINDINGS\n\n"
        )

        for item in analysis["log_analysis"]["findings"]:

            findings.insert(
                "end",
                f"✓ {item['description']}\n"
            )

        findings.configure(
            state="disabled"
        )

        # ----------------------------
        # AI Summary
        # ----------------------------

        summary = ctk.CTkTextbox(
            dashboard,
            height=150
        )

        summary.pack(
            fill="x",
            pady=15
        )

        summary.insert(
            "end",
            "AI INVESTIGATION SUMMARY\n\n"
        )

        for line in analysis["correlation"]["summary"]:

            summary.insert(
                "end",
                f"• {line}\n"
            )

        summary.configure(
            state="disabled"
        )

        # ----------------------------
        # Timeline
        # ----------------------------

        timeline = ctk.CTkTextbox(
            dashboard,
            height=220
        )

        timeline.pack(
            fill="x",
            pady=15
        )

        timeline.insert(
            "end",
            "ATTACK TIMELINE\n\n"
        )

        for event in analysis["correlation"]["timeline"]:

            timeline.insert(
                "end",
                f"{event['timestamp']} : {event['event']}\n"
            )

        timeline.configure(
            state="disabled"
        )

        # ----------------------------
        # Report Buttons
        # ----------------------------

        buttons = ctk.CTkFrame(
            dashboard,
            fg_color="transparent"
        )

        buttons.pack(
            pady=20
        )

        report_path = analysis["report"]

        open_btn = ctk.CTkButton(
            buttons,
            text="Open PDF Report",
            command=lambda: open_report(report_path),
            width=220
        )

        open_btn.pack(
            side="left",
            padx=10
        )

        new_btn = ctk.CTkButton(
            buttons,
            text="New Investigation",
            command=self.master.master.show_upload,
            width=220
        )

        new_btn.pack(
            side="left",
            padx=10
        )