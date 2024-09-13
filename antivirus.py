import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests
import json
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import io
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import threading

# Function to read the API key from the file
def read_api_key():
    try:
        with open("api-key.txt", "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "API key file not found.")
        root.destroy()
        return None

# Function to display the current date and time
def update_time():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    time_label.config(text=f"Current Date and Time:\n{now}")
    root.after(1000, update_time)  # Update every second

# Function to handle file selection
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

# Function to analyze the selected file and display results
def analyze_file(file_path=None):
    if not file_path:
        file_path = file_entry.get()
    api_key = read_api_key()
    if not api_key or not file_path:
        return

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    try:
        with open(file_path, "rb") as file_to_upload:
            params = {"apikey": api_key}
            files = {'file': file_to_upload}
            response = requests.post(url, files=files, params=params)
            response.raise_for_status()
            file_info = response.json()
            file_id = file_info['resource']
            file_url = f"https://www.virustotal.com/api/v3/files/{file_id}"

        headers = {"accept": "application/json", "x-apikey": api_key}
        status_text.config(state=tk.NORMAL)
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, "Analyzing...\n")
        status_text.config(state=tk.DISABLED)

        response = requests.get(file_url, headers=headers)
        response.raise_for_status()
        report = response.json()

        attributes = report["data"]["attributes"]
        name = attributes.get("meaningful_name", "Unable to fetch")
        hash_value = attributes.get("sha256", "N/A")
        descp = attributes.get("type_description", "N/A")
        size = attributes.get("size", 0) * 10**-3
        result = attributes.get("last_analysis_results", {})

        # Analysis results and plotting
        verdict_counts = {"undetected": 0, "type-unsupported": 0, "malicious": 0, "other": 0}

        for key, values in result.items():
            verdict = values['category']
            if verdict in verdict_counts:
                verdict_counts[verdict] += 1
            else:
                verdict_counts["other"] += 1

        result_text = f"Name: {name}\nHash: {hash_value}\nDescription: {descp}\nSize: {size:.2f} KB\n\n"
        result_text += "\n".join([f"{key}: {verdict_counts[key]}" for key in verdict_counts])

        if verdict_counts["malicious"] != 0:
            result_text += f"\n\n{verdict_counts['malicious']} antivirus detected the file as malicious!"
        else:
            result_text += "\n\nNo antivirus detected the file as malicious!"

        status_text.config(state=tk.NORMAL)
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, result_text)
        status_text.config(state=tk.DISABLED)

        # Plotting the results
        plot_results(verdict_counts)

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Request Error", f"Request failed: {e}")
    except FileNotFoundError:
        messagebox.showerror("File Error", "The specified file was not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to plot the scan results
def plot_results(verdict_counts):
    # Ensure this code runs on the main thread
    def plot_on_main_thread():
        labels = list(verdict_counts.keys())
        sizes = list(verdict_counts.values())
        colors = ['#ff6666','#ff9999','#ffcccc','#ffe6e6']

        fig, ax = plt.subplots(figsize=(8, 6))
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140, pctdistance=0.85)

        # Draw a circle at the center of the pie to make it look like a donut
        centre_circle = plt.Circle((0,0),0.70,fc='white')
        fig.gca().add_artist(centre_circle)

        # Improve the appearance of the labels
        for text in texts:
            text.set_fontsize(12)
            text.set_color('black')
        for autotext in autotexts:
            autotext.set_fontsize(12)
            autotext.set_color('black')

        ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

        # Draw the pie chart in the Tkinter window
        for widget in chart_frame.winfo_children():
            widget.destroy()

        canvas = FigureCanvasTkAgg(fig, master=chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    root.after(0, plot_on_main_thread)  # Schedule the plotting on the main thread

# Function to handle "Contact Developer"
def contact_developer():
    messagebox.showinfo("Contact Developer", "You can contact the developer at: developer@example.com")

# Function to handle "Update App"
def update_app():
    messagebox.showinfo("Update App", "Checking for updates...")

# Function to handle "Buy Premium Subscription"
def buy_premium():
    messagebox.showinfo("Premium Subscription", "Visit our website to purchase a premium subscription.")

# Function to show the home screen (landing page)
def home():
    scan_frame.pack_forget()  # Hide the scan frame
    landing_frame.pack(fill=tk.BOTH, expand=True)  # Show the landing frame
    landing_frame.tkraise()  # Bring the landing frame to the front

# Function to toggle the sidebar
def toggle_sidebar():
    global sidebar_open
    if sidebar_open:
        sidebar_frame.pack_forget()
        main_frame.pack(fill=tk.BOTH, expand=True)
        sidebar_button.config(text="Open Sidebar")
    else:
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        sidebar_button.config(text="Close Sidebar")
    sidebar_open = not sidebar_open

# Function to switch to the scan page
def switch_to_scan_page():
    landing_frame.pack_forget()  # Hide the landing frame
    scan_frame.pack(fill=tk.BOTH, expand=True)  # Show the scan frame
    scan_frame.tkraise()  # Bring the scan frame to the front

# Function to handle real-time file download prompts
def on_created(event):
    if event.src_path:
        result = messagebox.askyesno("New File Detected", f"A new file has been downloaded: {os.path.basename(event.src_path)}.\nWould you like to scan it for viruses?")
        if result:
            analyze_file(file_path=event.src_path)

# Function to start monitoring the download folder
def start_monitoring(download_folder):
    event_handler = FileSystemEventHandler()
    event_handler.on_created = on_created
    observer = Observer()
    observer.schedule(event_handler, path=download_folder, recursive=False)
    observer.start()
    return observer

# Create the main application window
root = tk.Tk()
root.title("VirusTotal File Scanner")
root.geometry("1000x600")
root.configure(bg="#ffe6e6")

# Set the download folder path (modify this as needed)
download_folder = os.path.expanduser("~/Downloads")

# Start monitoring the download folder in a separate thread
monitoring_thread = threading.Thread(target=start_monitoring, args=(download_folder,), daemon=True)
monitoring_thread.start()

# Create the sidebar frame
sidebar_frame = tk.Frame(root, width=200, bg="#ff9999", height=600, relief="sunken", borderwidth=2)
sidebar_open = True

# Create the sidebar buttons
sidebar_buttons = tk.Frame(sidebar_frame, bg="#ff9999")

homes = tk.Button(sidebar_buttons, text="Home", command=home, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
homes.pack(pady=10, fill=tk.X)

scan_button = tk.Button(sidebar_buttons, text="Scan Now", command=switch_to_scan_page, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
scan_button.pack(pady=10, fill=tk.X)

contact_button = tk.Button(sidebar_buttons, text="Contact Developer", command=contact_developer, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
contact_button.pack(pady=10, fill=tk.X)

update_button = tk.Button(sidebar_buttons, text="Update App", command=update_app, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
update_button.pack(pady=10, fill=tk.X)

premium_button = tk.Button(sidebar_buttons, text="Buy Premium", command=buy_premium, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
premium_button.pack(pady=10, fill=tk.X)

sidebar_buttons.pack(pady=10)

# Sidebar toggle button
sidebar_button = tk.Button(root, text="Close Sidebar", command=toggle_sidebar, bg="#ff6666", fg="white", font=("Arial", 12, "bold"), height=2)
sidebar_button.pack(side=tk.TOP, fill=tk.X)

# Create the main content frame
main_frame = tk.Frame(root, bg="white")
main_frame.pack(fill=tk.BOTH, expand=True)

# Create the landing page frame
landing_frame = tk.Frame(main_frame, bg="white")
landing_frame.pack(fill=tk.BOTH, expand=True)

# Add a welcome message and current date/time to the landing page
welcome_label = tk.Label(landing_frame, text="Welcome Captain!This is a demo antivirus made by Kastab", bg="white", fg="#ff6666", font=("Arial", 18, "bold"))
welcome_label.pack(pady=20)

time_label = tk.Label(landing_frame, text="", bg="white", fg="#ff6666", font=("Arial", 14))
time_label.pack(pady=10)

update_time()  # Start updating the time

# Create the scan page frame
scan_frame = tk.Frame(main_frame, bg="white")

file_label = tk.Label(scan_frame, text="File Path:", bg="white", fg="#ff6666", font=("Arial", 12))
file_label.pack(pady=5)

file_entry = tk.Entry(scan_frame, width=50, font=("Arial", 12))
file_entry.pack(pady=5)

browse_button = tk.Button(scan_frame, text="Browse", command=select_file, bg="#ff6666", fg="white", font=("Arial", 12, "bold"))
browse_button.pack(pady=5)

analyze_button = tk.Button(scan_frame, text="Analyze", command=lambda: analyze_file(file_entry.get()), bg="#ff6666", fg="white", font=("Arial", 12, "bold"))
analyze_button.pack(pady=5)

status_text = scrolledtext.ScrolledText(scan_frame, width=70, height=15, wrap=tk.WORD, bg="lightgray", font=("Arial", 12), fg="black")
status_text.pack(pady=10)

chart_frame = tk.Frame(scan_frame, bg="white")
chart_frame.pack(fill=tk.BOTH, expand=True)

# Pack the sidebar initially
sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)

# Start the GUI event loop
root.mainloop()
