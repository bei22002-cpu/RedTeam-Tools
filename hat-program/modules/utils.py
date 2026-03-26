"""
Utility functions shared across all hat modules.
"""

import subprocess
import shutil
import os
import sys


# ANSI color codes
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_banner(text, color=Colors.WHITE):
    """Print a styled banner."""
    width = 60
    print(f"\n{color}{Colors.BOLD}{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}{Colors.RESET}\n")


def print_section(text, color=Colors.CYAN):
    """Print a section header."""
    print(f"\n{color}{Colors.BOLD}--- {text} ---{Colors.RESET}")


def print_info(text):
    """Print info message."""
    print(f"{Colors.GREEN}[+]{Colors.RESET} {text}")


def print_warning(text):
    """Print warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {text}")


def print_error(text):
    """Print error message."""
    print(f"{Colors.RED}[-]{Colors.RESET} {text}")


def print_status(text):
    """Print status message."""
    print(f"{Colors.BLUE}[*]{Colors.RESET} {text}")


def run_command(command, shell=True, timeout=60, capture=True):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def check_tool(tool_name):
    """Check if a tool is available on the system."""
    return shutil.which(tool_name) is not None


def check_root():
    """Check if running as root."""
    return os.geteuid() == 0


def require_root(func_name):
    """Print a warning if not running as root."""
    if not check_root():
        print_warning(f"'{func_name}' may require root privileges for full functionality.")
        print_warning("Consider running with: sudo python3 hat_program.py")
        return False
    return True


def get_user_input(prompt, default=None):
    """Get user input with optional default value."""
    if default:
        user_input = input(f"{Colors.CYAN}{prompt} [{default}]: {Colors.RESET}").strip()
        return user_input if user_input else default
    return input(f"{Colors.CYAN}{prompt}: {Colors.RESET}").strip()


def validate_ip(ip_string):
    """Basic IP address validation."""
    parts = ip_string.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True


def validate_port(port_string):
    """Validate a port number."""
    try:
        port = int(port_string)
        return 1 <= port <= 65535
    except ValueError:
        return False


def display_menu(title, options, color=Colors.CYAN):
    """Display a numbered menu and return the user's choice."""
    print_banner(title, color)
    for i, option in enumerate(options, 1):
        print(f"  {color}{Colors.BOLD}{i}.{Colors.RESET} {option}")
    print(f"  {color}{Colors.BOLD}0.{Colors.RESET} Back / Exit")
    print()

    while True:
        choice = get_user_input("Select an option")
        try:
            choice_num = int(choice)
            if 0 <= choice_num <= len(options):
                return choice_num
            print_error("Invalid option. Try again.")
        except ValueError:
            print_error("Please enter a number.")


def confirm_action(prompt):
    """Ask user to confirm an action."""
    response = get_user_input(f"{prompt} (y/n)", "n")
    return response.lower() in ("y", "yes")


def check_required_tools(tools):
    """Check multiple tools and report availability."""
    available = []
    missing = []
    for tool in tools:
        if check_tool(tool):
            available.append(tool)
        else:
            missing.append(tool)

    if available:
        print_info(f"Available tools: {', '.join(available)}")
    if missing:
        print_warning(f"Missing tools: {', '.join(missing)}")
        print_warning("Install missing tools for full functionality.")

    return available, missing
