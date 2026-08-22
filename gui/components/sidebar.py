import customtkinter as ctk


class Sidebar(ctk.CTkFrame):

    def __init__(self, master):

        super().__init__(master, width=220)

        self.master = master

        self.pack_propagate(False)

        title = ctk.CTkLabel(
            self,
            text="ForensicAgent",
            font=("Arial", 24, "bold")
        )

        title.pack(pady=30)

        home = ctk.CTkButton(
            self,
            text="Home",
            command=master.show_home
        )

        home.pack(
            fill="x",
            padx=20,
            pady=8
        )

        upload = ctk.CTkButton(
            self,
            text="Upload",
            command=master.show_upload
        )

        upload.pack(
            fill="x",
            padx=20,
            pady=8
        )