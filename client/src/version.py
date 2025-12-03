# client/src/version.py
"""
Central version configuration for Nexus C2 Framework.
Update VERSION_* and BUILD_DATE when releasing new versions.
"""

from datetime import datetime

# Semantic Versioning: MAJOR.MINOR.PATCH-PRERELEASE
VERSION_MAJOR = 0
VERSION_MINOR = 8
VERSION_PATCH = 0
VERSION_PRERELEASE = "beta" 

# Build information - UPDATE WHEN RELEASING
BUILD_DATE = "2025-12-03"   # Format: YYYY-MM-DD
BUILD_NUMBER = None         # Not used for releases

# Application information
APP_NAME = "Nexus"
APP_DESCRIPTION = "Command & Control Framework"
CODENAME = "Vulpecula"


def get_version_string():
    """Returns the full version string"""
    version = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"
    if VERSION_PRERELEASE:
        version += f"-{VERSION_PRERELEASE}"
    if BUILD_NUMBER:
        version += f"+{BUILD_NUMBER}"
    return version


def get_short_version():
    """Returns version without pre-release suffix or build number"""
    return f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"


def get_version_info():
    """Returns a dictionary with all version information"""
    return {
        "version": get_version_string(),
        "short_version": get_short_version(),
        "major": VERSION_MAJOR,
        "minor": VERSION_MINOR,
        "patch": VERSION_PATCH,
        "prerelease": VERSION_PRERELEASE,
        "build_date": BUILD_DATE,
        "build_number": BUILD_NUMBER,
        "app_name": APP_NAME,
        "description": APP_DESCRIPTION,
        "codename": CODENAME
    }


# For easy imports
__version__ = get_version_string()
__version_info__ = get_version_info()


if __name__ == "__main__":
    # For testing - run this file directly to see version info
    print(f"App: {APP_NAME}")
    print(f"Version: {get_version_string()}")
    print(f"Short Version: {get_short_version()}")
    print(f"Codename: {CODENAME}")
    print(f"Build Date: {BUILD_DATE}")
    print(f"\nWhat users see in version dialog:")
    print(f"  {APP_NAME}")
    print(f"  Version {get_version_string()} ({CODENAME})")
    print(f"  Build: {BUILD_DATE}")
    print(f"  {APP_DESCRIPTION}")