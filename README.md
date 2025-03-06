# ImGui DirectX 11 DLL Hook

## Overview
This project is a DirectX 11-based DLL hook using ImGui for creating an overlay. The overlay can be toggled using the `Home` key and currently demonstrates ImGui features like text, sliders, and buttons. It is designed to be injected into a target application using the Steam overlay.

## Features
- DirectX 11 rendering with ImGui
- Toggle overlay with the `Home` key
- Pattern scanning for dynamic function hooking
- Basic ImGui elements (text, button, slider)

## Prerequisites
- Visual Studio 2022
- DirectX 11 SDK
- ImGui library
- A target application with DirectX 11 support

## Building the Project
1. Clone the repository:
```sh
    git clone https://github.com/yourusername/overlay_discord.git
```

2. Open the solution file in Visual Studio.

3. Build the project in Release x64 mode.

## Injection
To use the DLL, inject it into the target process using your preferred DLL injector.

## Controls
- `Home` Key: Toggle the ImGui overlay on and off.

## How It Works
1. The DLL uses pattern scanning to locate the `Present` function in the `GameOverlayRenderer64.dll` module.
2. ImGui is initialized with the DirectX 11 device and swap chain.
3. When the `Home` key is pressed, the overlay is toggled.
4. ImGui elements are rendered on top of the target application.

## Known Issues
- Ensure the target application uses DirectX 11, or the hook may fail.
- The pattern scanner may need updating if the `GameOverlayRenderer64.dll` is updated.

## License
This project is licensed under the MIT License.

## Contributing
Feel free to open issues or submit pull requests to improve the overlay or add new features!

