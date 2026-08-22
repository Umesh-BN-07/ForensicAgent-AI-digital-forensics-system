import customtkinter as ctk


class HomePage(ctk.CTkFrame):

    def __init__(self, master):

        super().__init__(master)

        title = ctk.CTkLabel(
            self,
            text="AI Powered Digital Forensics Investigation",
            font=("Arial", 28, "bold")
        )

        title.pack(pady=30)

        subtitle = ctk.CTkLabel(
            self,
            text="Welcome to ForensicAgent",
            font=("Arial", 18)
        )

        subtitle.pack(pady=10)

        info = ctk.CTkTextbox(
            self,
            width=700,
            height=250
        )

        info.pack(pady=20)

        info.insert(
            "1.0",
            """
ForensicAgent

Features

✔ Evidence Upload

✔ SHA256 Integrity Verification

✔ Log Analysis

✔ Machine Learning Detection

✔ NLP Threat Detection

✔ Correlation Analysis

✔ PDF Report Generation
            """
        )

        info.configure(state="disabled")