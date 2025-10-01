import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vuln_checker import scan_vulnerabilities
from models import Issue, User, db

@patch('subprocess.run')
def test_scan_vulnerabilities(mock_run, app):
    # Mock subprocess.run to simulate test mode
    mock_process = MagicMock()
    mock_process.stdout = ""
    mock_process.returncode = 0
    mock_run.return_value = mock_process

    # Set test mode environment variable
    with patch.dict('os.environ', {'PYTEST_CURRENT_TEST': 'test_scan_vulnerabilities'}):
        results, osv_results = scan_vulnerabilities()

    # In test mode, expect empty results
    assert isinstance(results, dict)
    assert len(results) == 1
