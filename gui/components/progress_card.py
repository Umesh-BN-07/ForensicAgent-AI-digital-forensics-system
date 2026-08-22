import customtkinter as ctk


class ProgressCard(ctk.CTkFrame):

    def __init__(self, master, title, value):

        super().__init__(
            master,
            fg_color="#2B2B2B",
            corner_radius=15,
            width=350,
            height=140
        )

        self.pack_propagate(False)

        ctk.CTkLabel(
            self,
            text=title,
            font=("Arial", 18, "bold")
        ).pack(pady=(15, 5))

        self.progress = ctk.CTkProgressBar(
            self,
            width=280,
            height=18
        )

        self.progress.pack(pady=10)

        self.progress.set(value / 100)

        self.score = ctk.CTkLabel(
            self,
            text=f"{value}/100",
            font=("Arial", 28, "bold"),
            text_color="#FF5555"
        )

        self.score.pack()