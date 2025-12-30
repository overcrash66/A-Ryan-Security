import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_modules.firewall import check_firewall_status, add_rule, list_rules

@patch('subprocess.run')
def test_check_firewall_status(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Profile State: Active"
    mock_run.return_value = mock_process
    
    # Test successful firewall check
    result = check_firewall_status()
    assert "Profile State: Active" in result
    assert mock_run.called
    mock_run.assert_called_with('netsh advfirewall show allprofiles', 
                               capture_output=True, text=True, shell=True)

@patch('subprocess.run')
def test_check_firewall_status_error(mock_run):
    # Setup mock to raise exception
    mock_run.side_effect = Exception("Test error")
    
    # Test error handling
    result = check_firewall_status()
    assert "Test error" in result
    assert mock_run.called

@patch('subprocess.run')
def test_add_rule(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Ok."
    mock_run.return_value = mock_process
    
    # Test adding rule
    result = add_rule("TestRule", "in", "allow", "C:\\test.exe")
    assert "Ok." in result
    mock_run.assert_called_with(
        'netsh advfirewall firewall add rule name="TestRule" dir=in action=allow program="C:\\test.exe"',
        capture_output=True, text=True, shell=True
    )

@patch('subprocess.run')
def test_add_rule_without_program(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Ok."
    mock_run.return_value = mock_process
    
    # Test adding rule without program
    result = add_rule("TestRule", "out", "block")
    assert "Ok." in result
    mock_run.assert_called_with(
        'netsh advfirewall firewall add rule name="TestRule" dir=out action=block',
        capture_output=True, text=True, shell=True
    )

@patch('subprocess.run')
def test_add_rule_error(mock_run):
    # Setup mock to raise exception
    mock_run.side_effect = Exception("Test error")
    
    # Test error handling
    result = add_rule("TestRule", "in", "allow")
    assert "Test error" in result
    assert mock_run.called

@patch('subprocess.run')
def test_list_rules(mock_run):
    # Setup mock
    mock_process = MagicMock()
    mock_process.stdout = "Rule Name: TestRule"
    mock_run.return_value = mock_process
    
    # Test listing rules
    result = list_rules()
    assert "Rule Name: TestRule" in result
    mock_run.assert_called_with(
        'netsh advfirewall firewall show rule name=all',
        capture_output=True, text=True, shell=True
    )

@patch('subprocess.run')
def test_list_rules_error(mock_run):
    # Setup mock to raise exception
    mock_run.side_effect = Exception("Test error")
    
    # Test error handling
    result = list_rules()
    assert "Test error" in result
    assert mock_run.called
