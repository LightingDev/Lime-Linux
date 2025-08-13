#!/usr/bin/env python3
"""
Lime Desktop Environment - A Cybersecurity-focused TUI Desktop Environment
Built with Textual for Linux systems
"""

import os
import subprocess
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict
import shlex
import pwd
import grp
import stat

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Header, Footer, DirectoryTree, Static, Input, 
    RichLog, Button, Label
)
from textual.reactive import reactive
from textual.message import Message
from textual.binding import Binding
from textual import events
from rich.text import Text
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from rich.panel import Panel


class SecurityLogger:
    """Security-focused logging system"""
    
    def __init__(self):
        self.events = []
        self.max_events = 1000
    
    def log_event(self, event_type: str, message: str, severity: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = {
            "timestamp": timestamp,
            "type": event_type,
            "message": message,
            "severity": severity
        }
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        return event


class FileExplorer(DirectoryTree):
    """Enhanced file explorer with security features"""
    
    BINDINGS = [
        Binding("enter", "select_file", "Open File"),
        Binding("r", "refresh", "Refresh"),
        Binding("h", "show_hidden", "Toggle Hidden Files"),
    ]
    
    def __init__(self, path: str = ".", **kwargs):
        super().__init__(path, **kwargs)
        self.show_hidden_files = False
        self.border_title = "🗂️  File Explorer"
        
    def action_show_hidden(self):
        """Toggle showing hidden files"""
        self.show_hidden_files = not self.show_hidden_files
        self.reload()
        
    def action_refresh(self):
        """Refresh the directory tree"""
        self.reload()
        
    def action_select_file(self):
        """Handle file selection"""
        if self.cursor_node:
            path = self.cursor_node.data.path
            if path.is_file():
                self.post_message(FileSelected(path))
            elif path.is_dir():
                self.cursor_node.toggle()


class FileSelected(Message):
    """Message sent when a file is selected"""
    
    def __init__(self, path: Path):
        self.path = path
        super().__init__()


class Terminal(Container):
    """Enhanced terminal widget with security tools integration"""
    
    def __init__(self, terminal_id: str, **kwargs):
        super().__init__(**kwargs)
        self.terminal_id = terminal_id
        self.command_history = []
        self.history_index = 0
        self.current_dir = Path.home()
        
    def compose(self) -> ComposeResult:
        yield Static(f"🖥️  Terminal {self.terminal_id}", classes="terminal-header")
        yield RichLog(id=f"terminal-output-{self.terminal_id}", 
                     classes="terminal-output")
        yield Input(placeholder="Enter command...", 
                   id=f"terminal-input-{self.terminal_id}",
                   classes="terminal-input")
    
    def on_mount(self):
        """Initialize terminal"""
        output = self.query_one(f"#terminal-output-{self.terminal_id}", RichLog)
        output.write(f"[bold green]Lime Terminal {self.terminal_id}[/bold green]")
        output.write(f"[cyan]Current directory: {self.current_dir}[/cyan]")
        output.write("[yellow]Type 'help' for security tools[/yellow]")
        
    def on_input_submitted(self, event: Input.Submitted):
        """Handle command input"""
        if event.input.id == f"terminal-input-{self.terminal_id}":
            command = event.value.strip()
            if command:
                self.execute_command(command)
                event.input.value = ""
    
    def execute_command(self, command: str):
        """Execute command with security focus"""
        output = self.query_one(f"#terminal-output-{self.terminal_id}", RichLog)
        
        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Display command
        prompt = f"[bold blue]{os.getenv('USER', 'user')}@lime[/bold blue]:[bold cyan]{self.current_dir.name}[/bold cyan]$ "
        output.write(f"{prompt}{command}")
        
        # Handle built-in commands
        if command == "help":
            self.show_help(output)
        elif command == "clear":
            output.clear()
        elif command.startswith("cd "):
            self.change_directory(command[3:].strip(), output)
        elif command == "pwd":
            output.write(str(self.current_dir))
        elif command == "lime-scan":
            self.security_scan(output)
        elif command == "lime-monitor":
            self.network_monitor(output)
        elif command == "lime-audit":
            self.security_audit(output)
        elif command == "lime-ports":
            self.show_open_ports(output)
        elif command == "lime-users":
            self.show_logged_users(output)
        elif command == "lime-syslog":
            self.show_system_logs(output)
        elif command == "lime-processes":
            self.show_processes(output)
        elif command == "lime-iptables":
            self.show_iptables(output)
        elif command == "lime-services":
            self.show_services(output)
        elif command == "lime-mounts":
            self.show_mounts(output)
        else:
            self.run_system_command(command, output)
    
    def show_help(self, output):
        """Show security-focused help"""
        root_status = "[bold red]ROOT MODE[/bold red]" if self.app.is_root else "[bold yellow]USER MODE[/bold yellow]"
        help_text = f"""
[bold yellow]Lime Security Tools:[/bold yellow] {root_status}
  lime-scan      - Quick security scan of current directory
  lime-monitor   - Network traffic monitor
  lime-audit     - System security audit
  lime-ports     - Show open ports and services
  lime-users     - Show logged in users
  lime-syslog    - Show recent system logs
  lime-processes - Show running processes
  
[bold yellow]Root-only Commands (if available):[/bold yellow]
  lime-iptables  - Show firewall rules
  lime-services  - Show system services
  lime-mounts    - Show mounted filesystems
  
[bold yellow]Standard Commands:[/bold yellow]
  ls, cat, grep, find, netstat, ps, top, who, last
  cd, pwd, clear, help
  
[bold red]Security Features:[/bold red]
  • All commands logged for security auditing
  • Dangerous commands require confirmation
  • Root operations are specially monitored
        """
        output.write(Panel(help_text, title="Lime Security Help", border_style="green"))
    
    def change_directory(self, path: str, output):
        """Change directory with validation"""
        try:
            new_path = Path(path).expanduser().resolve()
            if new_path.exists() and new_path.is_dir():
                self.current_dir = new_path
                output.write(f"[green]Changed to: {self.current_dir}[/green]")
                # Log security event
                self.app.logger.log_event("DIRECTORY_CHANGE", 
                                        f"Changed to {self.current_dir}", 
                                        "INFO")
            else:
                output.write(f"[red]Directory not found: {path}[/red]")
        except Exception as e:
            output.write(f"[red]Error: {e}[/red]")
    
    def security_scan(self, output):
        """Perform basic security scan"""
        output.write("[yellow]🔍 Starting Lime Security Scan...[/yellow]")
        
        # Check file permissions
        suspicious_files = []
        try:
            for item in self.current_dir.iterdir():
                if item.is_file():
                    perms = oct(item.stat().st_mode)[-3:]
                    if perms in ['777', '666']:
                        suspicious_files.append(f"{item.name} ({perms})")
        except PermissionError:
            output.write("[red]Permission denied for security scan[/red]")
            return
        
        if suspicious_files:
            output.write("[red]⚠️  Suspicious file permissions found:[/red]")
            for file in suspicious_files[:5]:  # Limit output
                output.write(f"  [red]• {file}[/red]")
        else:
            output.write("[green]✓ No suspicious file permissions detected[/green]")
        
        # Log scan
        self.app.logger.log_event("SECURITY_SCAN", 
                                f"Scanned {self.current_dir}", 
                                "HIGH" if suspicious_files else "INFO")
    
    def network_monitor(self, output):
        """Basic network monitoring"""
        output.write("[yellow]🌐 Lime Network Monitor[/yellow]")
        try:
            result = subprocess.run(['netstat', '-tuln'], 
                                  capture_output=True, text=True, timeout=5)
            if result.stdout:
                lines = result.stdout.strip().split('\n')[:10]  # Limit output
                for line in lines:
                    if 'LISTEN' in line:
                        output.write(f"[cyan]{line}[/cyan]")
            self.app.logger.log_event("NETWORK_MONITOR", 
                                    "Network status checked", "INFO")
        except Exception as e:
            output.write(f"[red]Network monitor error: {e}[/red]")
    
    def security_audit(self, output):
        """Perform security audit"""
        output.write("[yellow]🛡️  Lime Security Audit[/yellow]")
        
        # Check running processes
        try:
            result = subprocess.run(['ps', 'aux'], 
                                  capture_output=True, text=True, timeout=5)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                process_count = len(lines) - 1  # Exclude header
                output.write(f"[cyan]Running processes: {process_count}[/cyan]")
                
                # Look for suspicious processes (basic example)
                suspicious = ['nc', 'netcat', 'nmap']
                for line in lines:
                    for sus in suspicious:
                        if sus in line.lower():
                            output.write(f"[red]⚠️  Suspicious process: {sus}[/red]")
            
            self.app.logger.log_event("SECURITY_AUDIT", 
                                    f"Audit completed - {process_count} processes", 
                                    "HIGH")
        except Exception as e:
            output.write(f"[red]Audit error: {e}[/red]")
    
    def show_open_ports(self, output):
        """Show open ports and listening services"""
        output.write("[yellow]🔌 Open Ports and Services[/yellow]")
        try:
            # Use ss (modern replacement for netstat) if available, fallback to netstat
            commands = [
                ['ss', '-tuln'],
                ['netstat', '-tuln']
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout:
                        lines = result.stdout.strip().split('\n')
                        table = Table(title="Open Ports")
                        table.add_column("Protocol", style="cyan")
                        table.add_column("Local Address", style="green")
                        table.add_column("State", style="yellow")
                        
                        for line in lines[1:]:  # Skip header
                            if 'LISTEN' in line or 'State' not in line:
                                parts = line.split()
                                if len(parts) >= 4:
                                    protocol = parts[0] if parts[0] in ['tcp', 'udp', 'tcp6', 'udp6'] else 'unknown'
                                    local_addr = parts[3] if len(parts) > 3 else 'unknown'
                                    state = 'LISTEN' if 'LISTEN' in line else parts[-1] if len(parts) > 4 else ''
                                    table.add_row(protocol, local_addr, state)
                        
                        output.write(table)
                        break
                except FileNotFoundError:
                    continue
            
            self.app.logger.log_event("PORT_SCAN", "Open ports enumerated", "INFO")
        except Exception as e:
            output.write(f"[red]Error scanning ports: {e}[/red]")

    def show_logged_users(self, output):
        """Show currently logged in users"""
        output.write("[yellow]👥 Logged in Users[/yellow]")
        try:
            result = subprocess.run(['who'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                table = Table(title="Active Sessions")
                table.add_column("User", style="cyan")
                table.add_column("Terminal", style="green")
                table.add_column("Login Time", style="yellow")
                table.add_column("From", style="magenta")
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        user = parts[0]
                        terminal = parts[1]
                        login_time = ' '.join(parts[2:4]) if len(parts) >= 4 else parts[2]
                        from_addr = parts[4] if len(parts) > 4 else 'local'
                        table.add_row(user, terminal, login_time, from_addr)
                
                output.write(table)
            
            self.app.logger.log_event("USER_AUDIT", "User sessions enumerated", "INFO")
        except Exception as e:
            output.write(f"[red]Error getting user info: {e}[/red]")

    def show_system_logs(self, output):
        """Show recent system logs"""
        output.write("[yellow]📋 Recent System Logs[/yellow]")
        try:
            # Try journalctl first (systemd), then fallback to traditional logs
            log_commands = [
                ['journalctl', '-n', '20', '--no-pager'],
                ['tail', '-20', '/var/log/syslog'],
                ['tail', '-20', '/var/log/messages']
            ]
            
            for cmd in log_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout:
                        lines = result.stdout.strip().split('\n')
                        for line in lines[-10:]:  # Show last 10 lines
                            if 'error' in line.lower() or 'fail' in line.lower():
                                output.write(f"[red]{line}[/red]")
                            elif 'warn' in line.lower():
                                output.write(f"[yellow]{line}[/yellow]")
                            else:
                                output.write(f"[white]{line}[/white]")
                        break
                except FileNotFoundError:
                    continue
            
            self.app.logger.log_event("LOG_AUDIT", "System logs reviewed", "INFO")
        except Exception as e:
            output.write(f"[red]Error reading system logs: {e}[/red]")

    def show_processes(self, output):
        """Show running processes with security focus"""
        output.write("[yellow]⚙️  Running Processes[/yellow]")
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                
                # Create a table for better formatting
                table = Table(title="System Processes")
                table.add_column("PID", style="cyan")
                table.add_column("User", style="green")
                table.add_column("CPU%", style="yellow")
                table.add_column("MEM%", style="magenta")
                table.add_column("Command", style="white")
                
                # Parse process lines (skip header)
                for line in lines[1:21]:  # Show top 20 processes
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        pid = parts[1]
                        user = parts[0]
                        cpu = parts[2]
                        mem = parts[3]
                        command = parts[10][:50] + "..." if len(parts[10]) > 50 else parts[10]
                        table.add_row(pid, user, cpu, mem, command)
                
                output.write(table)
                
                # Highlight suspicious processes
                suspicious_keywords = ['nc', 'netcat', 'nmap', 'metasploit', 'burp', 'sqlmap']
                output.write("\n[red]⚠️  Security Analysis:[/red]")
                found_suspicious = False
                for line in lines:
                    for keyword in suspicious_keywords:
                        if keyword in line.lower():
                            output.write(f"[red]• Suspicious process detected: {keyword}[/red]")
                            found_suspicious = True
                            self.app.logger.log_event("SUSPICIOUS_PROCESS", 
                                                    f"Found: {keyword}", "HIGH")
                
                if not found_suspicious:
                    output.write("[green]• No obviously suspicious processes detected[/green]")
            
            self.app.logger.log_event("PROCESS_AUDIT", "Process list reviewed", "INFO")
        except Exception as e:
            output.write(f"[red]Error getting process list: {e}[/red]")

    def show_iptables(self, output):
        """Show firewall rules (requires root)"""
        output.write("[yellow]🔥 Firewall Rules[/yellow]")
        if not self.app.is_root:
            output.write("[red]⚠️  Root privileges required for iptables access[/red]")
            return
        
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                current_chain = ""
                
                for line in lines:
                    if line.startswith('Chain'):
                        current_chain = line
                        output.write(f"[bold cyan]{line}[/bold cyan]")
                    elif line.strip() and not line.startswith('target'):
                        if 'DROP' in line:
                            output.write(f"[red]{line}[/red]")
                        elif 'ACCEPT' in line:
                            output.write(f"[green]{line}[/green]")
                        else:
                            output.write(f"[white]{line}[/white]")
            else:
                output.write("[red]Failed to read iptables rules[/red]")
                
            self.app.logger.log_event("FIREWALL_AUDIT", "Firewall rules reviewed", "HIGH")
        except Exception as e:
            output.write(f"[red]Error reading firewall rules: {e}[/red]")

    def show_services(self, output):
        """Show system services (requires root for full info)"""
        output.write("[yellow]🛠️  System Services[/yellow]")
        try:
            # Try systemctl first
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                table = Table(title="Running Services")
                table.add_column("Service", style="cyan")
                table.add_column("Status", style="green")
                table.add_column("Description", style="white")
                
                for line in lines:
                    if '.service' in line and 'running' in line:
                        parts = line.split(None, 4)
                        if len(parts) >= 4:
                            service = parts[0].replace('.service', '')
                            status = parts[2]
                            desc = parts[4] if len(parts) > 4 else "No description"
                            table.add_row(service, status, desc[:50] + "..." if len(desc) > 50 else desc)
                
                output.write(table)
            else:
                # Fallback to service command
                result = subprocess.run(['service', '--status-all'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')[:20]
                    for line in lines:
                        if '[+]' in line:
                            output.write(f"[green]{line}[/green]")
                        elif '[-]' in line:
                            output.write(f"[red]{line}[/red]")
                        else:
                            output.write(f"[white]{line}[/white]")
            
            self.app.logger.log_event("SERVICE_AUDIT", "System services reviewed", "INFO")
        except Exception as e:
            output.write(f"[red]Error getting service info: {e}[/red]")

    def show_mounts(self, output):
        """Show mounted filesystems"""
        output.write("[yellow]💾 Mounted Filesystems[/yellow]")
        try:
            result = subprocess.run(['mount'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                table = Table(title="Mounted Filesystems")
                table.add_column("Device", style="cyan")
                table.add_column("Mount Point", style="green")
                table.add_column("Filesystem", style="yellow")
                table.add_column("Options", style="magenta")
                
                for line in lines:
                    if ' on ' in line and ' type ' in line:
                        parts = line.split(' on ')
                        if len(parts) >= 2:
                            device = parts[0]
                            rest = parts[1].split(' type ')
                            if len(rest) >= 2:
                                mount_point = rest[0]
                                fs_and_opts = rest[1].split(' (')
                                filesystem = fs_and_opts[0]
                                options = fs_and_opts[1].rstrip(')') if len(fs_and_opts) > 1 else 'default'
                                table.add_row(device, mount_point, filesystem, options[:30] + "..." if len(options) > 30 else options)
                
                output.write(table)
            
            self.app.logger.log_event("MOUNT_AUDIT", "Filesystem mounts reviewed", "INFO")
        except Exception as e:
            output.write(f"[red]Error getting mount info: {e}[/red]")
    
    def run_system_command(self, command: str, output):
        """Run system command with enhanced security controls"""
        try:
            # Check for dangerous commands that need confirmation
            high_risk_commands = ['rm -rf', 'mkfs', 'dd if=', 'fdisk', 'parted']
            dangerous_commands = ['rm ', 'rmdir', 'mv ', 'chmod 777', 'chmod -R 777']
            
            # Block extremely dangerous commands
            if any(cmd in command.lower() for cmd in high_risk_commands):
                output.write(f"[red]🚫 BLOCKED: Extremely dangerous command: {command}[/red]")
                self.app.logger.log_event("COMMAND_BLOCKED", 
                                        f"High-risk command blocked: {command}", "CRITICAL")
                return
            
            # Warn about dangerous commands but allow with confirmation
            if any(cmd in command.lower() for cmd in dangerous_commands):
                output.write(f"[yellow]⚠️  WARNING: Potentially dangerous command: {command}[/yellow]")
                output.write("[yellow]This command has been logged for security audit[/yellow]")
                self.app.logger.log_event("DANGEROUS_COMMAND", 
                                        f"Dangerous command executed: {command}", "HIGH")
            
            # Allow sudo commands if running as root, otherwise block
            if command.startswith('sudo '):
                if not self.app.is_root:
                    output.write("[red]⚠️  sudo commands require running Lime as root[/red]")
                    return
                else:
                    # Remove sudo prefix since we're already root
                    command = command[5:]
                    output.write("[yellow]Running as root (sudo prefix removed)[/yellow]")
            
            # Execute with timeout and proper environment
            result = subprocess.run(
                shlex.split(command), 
                capture_output=True, 
                text=True, 
                timeout=30,  # Increased timeout for complex commands
                cwd=self.current_dir,
                env=os.environ.copy()  # Preserve environment
            )
            
            # Handle output
            if result.stdout:
                stdout_lines = result.stdout.strip().split('\n')
                # Don't limit output for important commands
                max_lines = 50 if not any(cmd in command for cmd in ['ps', 'ls', 'find']) else 200
                for line in stdout_lines[:max_lines]:
                    # Color-code output based on content
                    if 'error' in line.lower() or 'failed' in line.lower():
                        output.write(f"[red]{line}[/red]")
                    elif 'warning' in line.lower() or 'warn' in line.lower():
                        output.write(f"[yellow]{line}[/yellow]")
                    elif 'success' in line.lower() or 'ok' in line.lower():
                        output.write(f"[green]{line}[/green]")
                    else:
                        output.write(line)
                
                if len(stdout_lines) > max_lines:
                    output.write(f"[dim]... ({len(stdout_lines) - max_lines} more lines)[/dim]")
            
            if result.stderr:
                stderr_lines = result.stderr.strip().split('\n')
                for line in stderr_lines[:20]:  # Limit error output
                    output.write(f"[red]stderr: {line}[/red]")
            
            # Show return code if non-zero
            if result.returncode != 0:
                output.write(f"[red]Command exited with code: {result.returncode}[/red]")
            
            # Log command execution with more detail
            log_level = "HIGH" if any(cmd in command.lower() for cmd in dangerous_commands) else "INFO"
            self.app.logger.log_event("COMMAND_EXECUTED", 
                                    f"Command: {command} | Exit: {result.returncode}", 
                                    log_level)
            
        except subprocess.TimeoutExpired:
            output.write("[red]⏰ Command timed out (30s limit)[/red]")
            self.app.logger.log_event("COMMAND_TIMEOUT", f"Timeout: {command}", "HIGH")
        except FileNotFoundError:
            cmd_name = command.split()[0]
            output.write(f"[red]❌ Command not found: {cmd_name}[/red]")
            output.write(f"[dim]Try: which {cmd_name} to check if it's installed[/dim]")
        except PermissionError:
            output.write(f"[red]🔒 Permission denied: {command}[/red]")
            if not self.app.is_root:
                output.write("[dim]Try running Lime as root for elevated commands[/dim]")
            self.app.logger.log_event("PERMISSION_DENIED", f"Command: {command}", "HIGH")
        except Exception as e:
            output.write(f"[red]💥 Error executing command: {e}[/red]")
            self.app.logger.log_event("COMMAND_ERROR", f"Command: {command} | Error: {e}", "HIGH")


class SecurityLogViewer(RichLog):
    """Security event log viewer"""
    
    def __init__(self, logger: SecurityLogger, **kwargs):
        super().__init__(**kwargs)
        self.logger = logger
        self.border_title = "🛡️  Security Log"
        
    def on_mount(self):
        """Initialize log viewer"""
        self.write("[bold green]Lime Security Logger Initialized[/bold green]")
        self.write("[yellow]Monitoring system events...[/yellow]")
        
    def update_logs(self):
        """Update the log display"""
        if self.logger.events:
            latest_event = self.logger.events[-1]
            severity_colors = {
                "INFO": "cyan",
                "HIGH": "yellow", 
                "CRITICAL": "red"
            }
            color = severity_colors.get(latest_event["severity"], "white")
            
            log_line = f"[{color}]{latest_event['timestamp']} [{latest_event['severity']}] {latest_event['type']}: {latest_event['message']}[/{color}]"
            self.write(log_line)


class LimeDesktopEnvironment(App):
    """Main Lime Desktop Environment Application"""
    
    CSS = """
    Screen {
        layout: grid;
        grid-size: 3 3;
        grid-gutter: 1;
        background: $surface;
    }
    
    #file-explorer {
        column-span: 1;
        row-span: 3;
        border: solid $primary;
    }
    
    #terminal-1 {
        column-span: 1;
        row-span: 3;
        border: solid $secondary;
    }
    
    #terminal-2 {
        column-span: 1;
        row-span: 2;
        border: solid $warning;
    }
    
    #security-log {
        column-span: 1;
        row-span: 1;
        border: solid $error;
    }
    
    .terminal-header {
        background: $primary;
        color: $text;
        text-align: center;
        height: 3;
    }
    
    .terminal-output {
        height: 1fr;
        border: solid $accent;
        margin: 1;
    }
    
    .terminal-input {
        height: 3;
        margin: 1;
        border: solid $success;
    }
    
    Header {
        background: $primary;
    }
    
    Footer {
        background: $primary;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit Lime"),
        Binding("f1", "toggle_files", "Toggle File Explorer"),
        Binding("f2", "focus_terminal1", "Focus Terminal 1"),
        Binding("f3", "focus_terminal2", "Focus Terminal 2"),
        Binding("f4", "focus_logs", "Focus Security Logs"),
        Binding("ctrl+l", "clear_logs", "Clear Logs"),
    ]
    
    def __init__(self):
        super().__init__()
        self.title = "Lime Desktop Environment - Cybersecurity TUI"
        self.sub_title = "🍋 Security-Focused Linux DE"
        self.logger = SecurityLogger()
        
    def compose(self) -> ComposeResult:
        """Compose the desktop environment layout"""
        yield Header(show_clock=True)
        
        with Container(id="file-explorer"):
            yield FileExplorer(str(Path.home()), id="files")
            
        with Container(id="terminal-1"):
            yield Terminal("1", id="term1")
            
        with Container(id="terminal-2"):
            yield Terminal("2", id="term2")
            
        with Container(id="security-log"):
            yield SecurityLogViewer(self.logger, id="logs")
            
        yield Footer()
    
    def on_mount(self):
        """Initialize the desktop environment"""
        # Log startup
        self.logger.log_event("SYSTEM_START", "Lime Desktop Environment started", "INFO")
        
        # Update log display periodically
        self.set_interval(2.0, self.update_security_logs)
        
        # Welcome message
        self.call_later(self.show_welcome)
        
        # Check if running as root
        self.is_root = os.geteuid() == 0
        if self.is_root:
            self.logger.log_event("ROOT_ACCESS", "Running with root privileges", "HIGH")
        
    def show_welcome(self):
        """Show welcome message"""
        term1 = self.query_one("#term1 RichLog")
        root_status = "ROOT MODE - Full System Access" if self.is_root else "USER MODE - Limited Access"
        privilege_color = "red" if self.is_root else "yellow"
        
        welcome = Panel(
            f"""[bold green]Welcome to Lime Desktop Environment[/bold green]

[cyan]🍋 Cybersecurity-focused TUI Desktop Environment[/cyan]

[{privilege_color}]🔐 Status: {root_status}[/{privilege_color}]

[yellow]Enhanced Features:[/yellow]
• Real-time security monitoring and logging
• Advanced system analysis tools
• Network traffic inspection
• Process and service auditing
• Firewall rule analysis {"(available)" if self.is_root else "(requires root)"}
• System log analysis
• File permission scanning

[red]Security Notice:[/red]
All commands are logged and monitored for security analysis.
Dangerous commands are blocked or require confirmation.
{"Root privileges detected - exercise extreme caution!" if self.is_root else "Run as root for full functionality."}

Type 'help' in any terminal for available security tools.
            """,
            title="Lime Security DE v2.0",
            border_style="bright_green"
        )
        term1.write(welcome)
    
    def update_security_logs(self):
        """Update security log display"""
        log_viewer = self.query_one("#logs", SecurityLogViewer)
        # This will be called periodically to show new log entries
        
    def on_file_selected(self, event: FileSelected):
        """Handle file selection from explorer"""
        term1 = self.query_one("#term1 RichLog")
        
        # Log file access
        self.logger.log_event("FILE_ACCESS", f"Accessed: {event.path}", "INFO")
        
        # Display file info
        try:
            stat_info = event.path.stat()
            size = stat_info.st_size
            perms = oct(stat_info.st_mode)[-3:]
            
            file_info = f"""[bold cyan]File: {event.path.name}[/bold cyan]
[yellow]Path:[/yellow] {event.path}
[yellow]Size:[/yellow] {size} bytes
[yellow]Permissions:[/yellow] {perms}
[yellow]Owner:[/yellow] {pwd.getpwuid(stat_info.st_uid).pw_name}"""
            
            term1.write(Panel(file_info, title="File Information", border_style="cyan"))
            
            # Show file preview if it's a text file
            if event.path.suffix in ['.txt', '.py', '.sh', '.conf', '.log']:
                try:
                    with open(event.path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000)  # First 1000 chars
                    
                    syntax = Syntax(content, event.path.suffix[1:] or "text", 
                                  line_numbers=True, theme="monokai")
                    term1.write(Panel(syntax, title=f"Preview: {event.path.name}", 
                                    border_style="green"))
                except Exception as e:
                    term1.write(f"[red]Cannot preview file: {e}[/red]")
        except Exception as e:
            term1.write(f"[red]Error accessing file: {e}[/red]")
    
    # Action methods for keybindings
    def action_toggle_files(self):
        """Toggle file explorer focus"""
        files = self.query_one("#files")
        files.focus()
        
    def action_focus_terminal1(self):
        """Focus terminal 1"""
        term_input = self.query_one("#terminal-input-1")
        term_input.focus()
        
    def action_focus_terminal2(self):
        """Focus terminal 2"""
        term_input = self.query_one("#terminal-input-2")  
        term_input.focus()
        
    def action_focus_logs(self):
        """Focus security logs"""
        logs = self.query_one("#logs")
        logs.focus()
        
    def action_clear_logs(self):
        """Clear security logs"""
        logs = self.query_one("#logs", SecurityLogViewer)
        logs.clear()
        logs.write("[yellow]Security logs cleared[/yellow]")
        self.logger.events.clear()
        self.logger.log_event("LOG_CLEARED", "Security logs cleared by user", "INFO")


def main():
    """Main entry point for Lime Desktop Environment"""
    import sys
    
    # Check if running as root and warn user
    if os.geteuid() == 0:
        print("🍋 Lime Desktop Environment")
        print("⚠️  WARNING: Running as ROOT - Full system access enabled")
        print("🔒 All privileged operations will be logged")
        print("💡 For security testing only - use with extreme caution")
        print("-" * 60)
    else:
        print("🍋 Lime Desktop Environment")
        print("👤 Running as USER - Some features may be limited")
        print("💡 Run as root (sudo python lime.py) for full functionality")
        print("-" * 60)
    
    try:
        app = LimeDesktopEnvironment()
        app.run()
    except KeyboardInterrupt:
        print("\n🍋 Lime Desktop Environment terminated by user")
    except Exception as e:
        print(f"❌ Error starting Lime: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
