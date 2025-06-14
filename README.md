# roa2-mod-hide-elo
This is a mod for the Steam version of Rivals of Aether II (Rivals 2) which hides your and your opponent's Elo rating from all interfaces. This change is only visible on your end (client-side), and does not affect your online opponents at all.

To use it, simply run the .exe file (which you can download from [here](https://github.com/Auride/roa2-mod-hide-elo/releases)) while Rivals 2 is running. Prior to mod version 2.0, running it again would toggle the mod off. After version 2.0, you must close and restart the game to disable the mod and see your Elo again.

To completely avoid seeing your Elo score, make sure to run the executable file before going past the first "Press Start" screen upon starting up the game. You can run the .exe file pretty much as soon as you see the black window (or fullscreen black) appear after starting Rivals of Aether II, but you may wish to wait until the ROA II game icon appears in your taskbar. You will know it worked if, in the top right of the main menu, you see only a Master icon (regardless of your actual rank) and no Elo number.

This mod makes no permanent changes to the game binary. It only modifies code in memory. **I do not guarantee that this is online safe**, but I'm pretty sure it is.

# Compatibility
This mod is compatible with these versions of ROA2 on Windows. You can check your version by looking in the bottom left corner from anywhere in the main menu.
- `hideElo-1.0`
  - 11-08-2024-12174 - [release]
- `hideElo-1.1`
  - 11-19-2024-12500 - [release]
- `hideElo-1.2`
  - 11-19-2024-12519 - [release]
- `hideElo-1.3`
  - 11-20-2024-12562 - [release]
- `hideElo-2.0`
  - Note: From this version onwards, the uses AOB scanning rather than static offsets, making it slower to apply (Around 1 second vs <50ms with previouss versions). The benefit is that it should continue working through most game updates.
  - 11-28-2024-12750 - [release]
  - 11-30-2024 12786 - [release]
- `hideElo-2.1`
  - version 1.1.3 - 02-18-2025 - 15113 - [release]
- `hideElo-2.2`
  - version 1.1.4 - 03-05-2025 - 15726 - [release]
- `hideElo-3.0`
  - version 1.2.0 - 04-08-2025 - 16911 - [release]
- `hideElo-3.1`
  - Note: The only difference between 3.1 and 3.0 is the removal of the Win Streak obfuscation patch, which caused lag for some users.
  - version 1.2.0 - 04-08-2025 - 16911 - [release]
  - version 1.2.1 - 04-25-2025 - 17377 - [release]
 - `hideElo-3.2` 
  - Note: This version adds 2 new patches to completely hide Win Streaks, which should avoid the lag seen in version 3.0.
  - version 1.2.2 - 05-09-2025 - 17811 - [release]


If your version is not listed, it may or may not be compatible with the latest version of the mod.

# How to build
A pre-built .exe file is provided under the [Releases](https://github.com/Auride/roa2-mod-hide-elo/releases) section for your convenience. If you wish to build the executable from source (e.g. because you want to modify the source file), follow these instructions:
1. Have the GCC C compiler.
   1. Open cmd.exe or Windows PowerShell at any directory. Run the command `gcc --version`.
   2. If you get a response like `gcc.exe (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r5) 13.2.0` you should be good to go to step 2.
   3. If you get an error, go to https://winlibs.com/ and download the version of GCC + MinGW labelled "**(LATEST)**". You most likely want the "Win64: 7-Zip archive". Save it anywhere.
   4. Open the folder you downloaded the .7z file to, then right click on it and click "Extract All..."
   5. In the window which opens, click "Browse" and then navigate to your `C:\` drive (or any other desired location), then click "Select Folder" and click the "Extract" button. Wait for a minute or two while it decompresses.
   6. Press the Windows key, then type "Env" and click "Edit the System Environment Variables". If this doesn't appear, open Windows Settings, click "System" in the top left, scroll down and click "About", click "Advanced System Settings" in the middle of the window, and click "Environment Variables" at the bottom of the smaller window which appears.
   7. In either the "User variables for &lt;username&gt;" or "System variables" section (it doesn't really matter which), find the "Path" variable, click it once, and then click "Edit...".
   9. On the top right of the small window which pops up, click "New", then type `C:\mingw64\bin`. If you extracted  the .7z file somewhere else, you'll need to find where, click "Browse..." after clicking New, then navigate to the bin file inside that location. Note that you must extract the .7z file first.
   10. Press "OK" until all those windows are closed.
2. Download the `hideElo-3.2.c` file anywhere.
3. Open file explorer to the folder you downloaded the .c file to.
4. Right click (or Shift + right click) anyhere in the folder *not* on a file, then click "Open in Terminal" or "Open PowerShell window here". There's no difference.
5. Type `gcc hideElo-3.2.c -o hideElo-3.2.exe` and press enter. This should generate the .exe file. It should be about 70 kilobytes (very small!).
6. Either double click the executable to run it, or in the same terminal window as before, type "./hideElo-3.2.exe". The latter will let you see the debug output of the mod.
   - **Note** As of version 3.0, you can rename the .exe file so that the part before the .exe ends in "r1" through "r8". This will change which ranked icon is displayed for all Elo values. r1 is Stone, r2 is Bronze, r8 is Grandmaster, etc.. By default, the Aetherian icon is used. For example, changing the name to `hideElo-3.2r1.exe` will cause it to patch the game to use the Stone icon everywhere instead of Aetherian. This is a purely aesthetic tweak.
