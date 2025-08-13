# Lime-Linux
A linux desktop environment made for hacking. Tui based.

**Lime** is a lightweight, Python-based **Terminal User Interface (TUI) Desktop Environment** built with [`textual`](https://github.com/Textualize/textual) and [`pyfiglet`](https://github.com/pwaller/pyfiglet). It’s designed for users who love a terminal-first workflow but still want a cohesive session that shows up in login managers like GDM/LightDM/SDDM.

---

## Features
- Pure TUI “desktop environment” experience
- Minimal resource usage
- Works from GUI display managers (runs in a terminal window) or directly on a TTY
- Simple, distro-agnostic installer
- Clean session integration via XDG `.desktop` entry

---

## Requirements
- Python **3.8+**
- Python packages: `textual`, `pyfiglet`
- A terminal emulator when launched from a graphical display manager (e.g., `xterm`)

---

## Install (from GitHub)
```bash
git clone https://github.com/Lightingdev/lime-de.git
cd lime-de
sudo bash install.sh
```

**What the installer does**
1. Verifies `python3`/`pip3`
2. Installs `textual` and `pyfiglet`
3. Installs `Lime.py` to `/opt/lime/`
4. Installs launcher `lime-session` to `/usr/local/bin/`
5. Registers the session file at `/usr/share/xsessions/Lime.desktop`

---

## Run
### From a display manager (GDM/LightDM/SDDM)
1. Log out
2. Click the session selector (gear icon)
3. Choose **Lime**
4. Log in

### From a TTY (no GUI)
```bash
lime-session
```

---

## File Layout
```
lime-de/
├── install.sh          # Installer (installs deps + registers session)
├── Lime.desktop        # XDG session file
├── lime-session        # Launcher script
└── Lime.py             # Your main TUI DE entrypoint
```

---

## Uninstall
```bash
sudo rm -f /usr/share/xsessions/Lime.desktop
sudo rm -f /usr/local/bin/lime-session
sudo rm -rf /opt/lime
pip3 uninstall -y textual pyfiglet
```

---

## Packaging (optional, for distro maintainers)

### Debian/Ubuntu (.deb)
- Create a `debian/` folder with `control`, `postinst`, `copyright`
- Install paths:
  - `/usr/share/xsessions/Lime.desktop`
  - `/usr/local/bin/lime-session`
  - `/opt/lime/Lime.py`
- Declare dependencies in `Depends:` (at least `python3`, `python3-pip`, and a terminal emulator like `xterm`)
- Build with `dpkg-deb --build` or `debuild -us -uc`

### Alpine (.apk)
- Create an `APKBUILD`
- Install to the same paths as above
- Add `depends="python3 py3-pip xterm"` (or your chosen terminal)
- Build with `abuild -r`

For universal distribution, keep distributing the repo with `install.sh`.

---

## Troubleshooting
- **Session doesn’t appear in the greeter**  
  Ensure `/usr/share/xsessions/Lime.desktop` exists and is readable.
- **Black screen or nothing happens after login**  
  Make sure a terminal emulator exists (e.g., `sudo apk add xterm` or `sudo apt install xterm`), and that `/usr/local/bin/lime-session` is executable.
- **Python import errors**  
  Re-run: `pip3 install --upgrade textual pyfiglet`

---

## Contributing
Pull requests and issues are welcome!

1. Fork the repo
2. Create a feature branch
3. Commit with clear messages
4. Open a PR describing your changes

---

## Security / Contact
Report issues or questions via GitHub or email.

- **Author**: Yixuan Xu (Lightingdev)  
- **GitHub**: https://github.com/Lightingdev  
- **Email**: xuyixuan370@gmail.com

---

## License
SPDX-License-Identifier: **GPL-3.0-or-later**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

---

## Acknowledgements
- [Textual](https://github.com/Textualize/textual)
- [pyfiglet](https://github.com/pwaller/pyfiglet)
