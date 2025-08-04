# Quest ADB File Manager GUI

A lightweight, open-source, dual-pane file manager for the Oculus Quest (1, 2, 3, Pro) and other Android devices. Built with Python and Tkinter, this tool provides a simple and transparent way to manage your files without installing bloated or suspicious software.

It allows you to connect wirelessly or via USB to your device and perform all essential file operations like transferring, deleting, and even moving files directly on the Quest itself.

![Quest ADB File Manager GUI](./Screenshot%202025-08-04%20133343.png)


## Why Use This?

For years, the options for managing Quest files have often been limited to clunky command-line operations or third-party Electron apps that can feel like overkill or, worse, potential malware. This tool was created to solve that problem.

-   **Lightweight & Fast:** No heavy frameworks, just a single Python script.
-   **Open-Source & Transparent:** The code is right here. You can see exactly what it does. No hidden trackers or mysterious processes.
-   **Powerful Features:** Goes beyond simple transfers with on-device moving, path scanning, and more.
-   **No Installation Needed:** Just run the Python script.

## Features

-   **Dual-Pane Layout:** Easily view your local PC files and Quest files side-by-side.
-   **Wireless & USB Connectivity:**
    -   Connect via USB for simplicity and charging.
    -   Connect wirelessly over your local network for convenience.
    -   Includes a "Find Quest IP" helper to automatically detect your Quest's IP address and enable wireless ADB.
-   **Full File & Folder Transfers:**
    -   Push files/folders from your PC to the Quest.
    -   Pull files/folders from the Quest to your PC.
    -   Supports transferring individually selected items or an entire directory's contents.
-   **File Management:**
    -   Delete selected files/folders on both your local PC and the Quest.
    -   **On-Device Move:** A powerful two-step process to move files and folders directly on the Quest without having to transfer them to your PC and back.
-   **User-Friendly Navigation:**
    -   Quick Access dropdown for common Quest directories (`Downloads`, `Android/obb`, etc.).
    -   "Scan Device Paths" feature to discover and add more accessible storage locations.
    -   "Up" buttons and double-click navigation.

## Prerequisites

1.  **Python 3:** The script is written in Python and uses the built-in `tkinter` library. No special packages are required.
2.  **ADB (Android Platform Tools):** This is essential. The script calls the `adb.exe` command.
    -   [Download the official Android Platform Tools from Google](https://developer.android.com/studio/releases/platform-tools).
    -   Unzip the folder to a permanent location (e.g., `C:\platform-tools`).
    -   **IMPORTANT:** Add this location to your system's `PATH` environment variable so the script can find `adb.exe`.
3.  **Developer Mode on Quest:** You must have Developer Mode enabled on your Quest.
    -   Go to the Meta Quest mobile app > Menu > Devices > Developer Mode, and turn it on.
    -   The first time you connect via USB, you will need to "Allow USB Debugging" inside the headset.

## How to Use

1.  **Clone or Download:** Get the `your_script_name.py` file from this repository.
2.  **Run the Script:** Open a terminal or command prompt and run `python your_script_name.py`.

### 1. Connecting to Your Quest

-   **Wireless Mode (Recommended):**
    1.  Ensure your Quest and PC are on the same Wi-Fi network.
    2.  Use the `oculuswirelessadb.apk` (like version 1.2) or a similar tool to easily enable Wireless ADB on your Quest. Alternatively, connect via USB first.
    3.  Click the **"Find Quest IP (via USB)"** button. This will use the USB connection to find your Quest's IP, enable wireless mode on port `5555`, and display the details.
    4.  Disconnect the USB cable.
    5.  Enter the IP and Port in the GUI and click **"Connect"**.
-   **USB Mode:**
    1.  Connect your Quest to your PC with a USB cable.
    2.  In the headset, accept the "Allow USB Debugging" prompt.
    3.  Select the "USB" radio button in the GUI and click **"Connect"**.

Once connected, the status will update and the Quest file pane will populate.

### 2. Transferring Files

-   **Select Items:** Click the checkbox `[ ]` next to any file or folder in either pane to select it. The box will change to `[☑]`.
-   **Transfer Selected:** Use the **"Transfer Selected"** buttons to move only the checked items.
-   **Transfer Folder:** Use the **"Transfer Current Folder"** buttons to move all contents of the currently displayed folder.

### 3. Deleting Files

1.  Select the items you wish to delete by checking their boxes.
2.  Click the **"Delete Selected"** button under the appropriate pane (Local or Quest).
3.  A confirmation dialog will appear. This action is permanent!

### 4. Moving Files on the Quest (On-Device Move)

This unique feature lets you reorganize files *on the Quest* without downloading and re-uploading them.

1.  **Select Source:** In the Quest file pane, navigate to the folder containing the items you want to move. Check the boxes `[☑]` for the files/folders.
2.  **Initiate Move:** Click the **"Move Selected (Quest)"** button. The button will change to **"Cancel Move Destination Select"** and the status bar will prompt you for the next step.
3.  **Navigate to Destination:** In the same Quest file pane, navigate to the folder where you want to move the items. You can go up directories or into sub-directories.
4.  **Set Destination:** Once you are inside the target directory, click the new **"Set Current as Move Destination"** button.
5.  **Confirm:** A final confirmation dialog will appear, summarizing the move. Click "Yes" to execute the `mv` command on the Quest.

The UI will reset, and the file view will refresh, showing the result of the move.

## Tips & Context

-   **Oculus Wireless ADB:** Using an app like `oculuswirelessadb 1.2.apk` on your Quest is highly recommended. It provides a simple toggle to turn wireless ADB on/off directly from your Unknown Sources library, making the initial connection much faster.
-   **Tailscale:** While tools like Tailscale are excellent for creating a secure network to push a single file directly to your headset from anywhere, this GUI excels at **managing directories**. It gives you the power to browse, clean up, and reorganize files in `Android/obb`, `Downloads`, and other folders—tasks that are cumbersome with direct push tools.

## Disclaimer

This is a powerful tool that can modify and delete files on your computer and your Quest. Use it carefully. The author is not responsible for any lost data. Always double-check your selections before deleting or moving files.

## License

This project is open-source and available under the [MIT License](LICENSE.md).
