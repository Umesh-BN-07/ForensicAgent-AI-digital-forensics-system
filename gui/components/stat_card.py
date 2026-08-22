import customtkinter as ctk


class StatCard(ctk.CTkFrame):

    def __init__(self, master, title, value, color):

        super().__init__(
            master,
            corner_radius=15,
            fg_color="#2B2B2B",
            width=250,
            height=120
        )

        self.pack_propagate(False)

        title_label = ctk.CTkLabel(
            self,
            text=title,
            font=("Arial", 16)
        )

        title_label.pack(pady=(15, 5))

        value_label = ctk.CTkLabel(
            self,
            text=value,
            font=("Arial", 28, "bold"),
            text_color=color
        )

        value_label.pack()