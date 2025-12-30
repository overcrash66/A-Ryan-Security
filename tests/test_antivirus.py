import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_modules.antivirus import scan_directory, extra_antivirus_layer

@patch('subprocess.run')
def test_scan_directory_success(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Scan completed successfully"
    mock_process.returncode = 0
    mock_run.return_value = mock_process
    
    # Test successful scan
    result = scan_directory('C:\\Test\\Path')
    assert "Scan completed successfully" in result
    mock_run.assert_called_with(
        ["powershell", "-Command", "Start-MpScan -ScanType CustomScan -ScanPath 'C:\\Test\\Path'"],
        capture_output=True,
        text=True
    )

@patch('subprocess.run')
def test_scan_directory_error(mock_run):
    # Setup mock to raise exception
    mock_run.side_effect = Exception("Access denied")
    
    # Test error handling
    result = scan_directory('C:\\Invalid\\Path')
    assert "Access denied" in result
    assert mock_run.called

@patch('subprocess.run')
@patch('os.getlogin')
def test_extra_antivirus_layer(mock_getlogin, mock_run):
    # Setup mocks
    mock_getlogin.return_value = 'testuser'
    mock_process = MagicMock()
    mock_process.stdout = "Scan result"
    mock_process.returncode = 0
    mock_run.return_value = mock_process
    
    # Call the function to scan
    results = extra_antivirus_layer()
    
    # Verify results
    assert isinstance(results, dict)
    assert mock_run.call_count == 2  # Two directories scanned
    assert results['C:\\Windows\\Temp'] == "Scan result"
    assert results[f'C:\\Users\\testuser\\Downloads'] == "Scan result"

@patch('subprocess.run')
@patch('os.getlogin')
def test_extra_antivirus_layer_partial_failure(mock_getlogin, mock_run):
    # Setup mocks
    mock_getlogin.return_value = 'testuser'
    
    def run_side_effect(*args, **kwargs):
        # args[0] is now the command list on index 0
        cmd_list = args[0]
        # The command string is at index 2 of the list
        if len(cmd_list) > 2 and 'Windows\\Temp' in cmd_list[2]:
            raise Exception("Scan failed")
        mock_process = MagicMock()
        mock_process.stdout = "Success"
        mock_process.returncode = 0
        return mock_process
        
    mock_run.side_effect = run_side_effect
    
    # Call the function to scan
    results = extra_antivirus_layer()
    
    # Verify results
    assert isinstance(results, dict)
    assert len(results) == 2  # Should return both results
    assert "Scan failed" in str(results['C:\\Windows\\Temp'])
    assert results[f'C:\\Users\\testuser\\Downloads'] == "Success"

@patch('subprocess.run')
def test_scan_directory_with_spaces(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Scan completed"
    mock_run.return_value = mock_process
    
    # Test path with spaces
    result = scan_directory('C:\\Test Path\\With Spaces')
    assert "Scan completed" in result
    # Verify the path was properly quoted in the command string (index 2 of args list)
    cmd_list = mock_run.call_args[0][0]
    assert "Start-MpScan" in cmd_list[2]
    assert "'C:\\Test Path\\With Spaces'" in cmd_list[2]
